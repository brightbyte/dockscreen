"""This module provides functions for finding and loading the project a compose command line selects, as
docker compose resolves it, and for gathering what the policy judges about it besides its config: where it is,
which containers have its name, and which configured mount directories are risky."""

import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from dockscreen.host import config
from dockscreen.host.docker import Docker, DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.model.project import Project, ProjectLocation
from dockscreen.policy import policy
from dockscreen.policy.finding import Finding, Reportable, Verdict
from dockscreen.policy.report import Report
from dockscreen.policy.rules.base import is_inside
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline

COMPOSE_FILE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
COMPOSE_VARS_IN_ENV_FILE = re.compile(r"^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=", re.MULTILINE)
# A directory that equals or contains one of these must not be mounted wholesale.
SENSITIVE_DIRS = ("/", "/etc", "/usr", "/var", "/boot", "/root", "/run", "/proc", "/sys", "/dev")
DOCKER_SOCKET = "/var/run/docker.sock"


class ProjectRefused(Exception):
    """Exception raised when the policy refuses a project before its config is looked at. It holds the
    policy's findings.

    Attributes:
    - findings: the refusals
    """

    def __init__(self, findings: Sequence[Finding]) -> None:
        super().__init__("; ".join(str(f) for f in findings))
        self.findings = list(findings)


def project(args: Sequence[str], runtime: Runtime) -> Project:
    """Returns the project args select, with its definition as compose resolves it.

    Raises ProjectRefused if the policy refuses where the project is (Policy.check_location); DockerError if
    compose cannot give the definition.

    Parameters:
    - args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    """
    location = locate(args, runtime)
    refusals = Screener(runtime).policy(location.directory).check_location(location)
    if refusals:
        raise ProjectRefused(refusals)
    return Project(_load_config(args, runtime.docker), location)


def locate(args: Sequence[str], runtime: Runtime) -> ProjectLocation:
    """Returns where the project args select is, as compose would find it.

    Raises DockerError if that cannot be found: the compose file is read from stdin, or there is none.

    Parameters:
    - args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command, whose current directory and environment compose would start from
    """
    location = _project_location(args, runtime.cwd, runtime)
    return location._replace(sensitive=tuple(_sensitive_inside(location.directory, runtime)))


def _sensitive_paths(runtime: Runtime) -> list[str]:
    """Returns the paths whose directories must not be mountable: system directories, the home
    directory, the config files and the docker socket.
    """
    return [*SENSITIVE_DIRS, runtime.home, config.SYSTEM_FILE, runtime.config_file, DOCKER_SOCKET]


def _sensitive_inside(directory: str, runtime: Runtime) -> list[str]:
    """Returns the sensitive paths that directory equals or contains, with symlinks resolved."""
    root = os.path.realpath(directory)
    return [path for path in _sensitive_paths(runtime) if is_inside(os.path.realpath(path), root)]


def sensitive_mount_dirs(runtime: Runtime) -> dict[str, list[str]]:
    """Returns the sensitive paths that each configured mount dir equals or contains, by mount dir, for
    Policy.check_mount_dirs.
    """
    return {directory: _sensitive_inside(directory, runtime)
            for directory in config.all_mount_dirs(runtime.settings)}


def passes(args: Sequence[str], runtime: Runtime,
           rules: Callable[[policy.Policy, Project], Sequence[Reportable]] = policy.Policy.check_project
           ) -> bool:
    """Tells whether rules(policy, project) finds nothing in the selected project, printing the verdict.

    Parameters:
    - args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    - rules: the checks to run: a Policy method that takes the project, check_project by default
    """
    try:
        found = project(args, runtime)
    except DockerError as e:
        return Report.failure(e).show_screening()
    except ProjectRefused as e:
        return Report.of(e.findings).show_screening()
    project_policy = Screener(runtime).project_policy(found)
    return Report.of(rules(project_policy, found)).show_screening()


def _load_config(global_args: Sequence[str], docker: Docker) -> dict[str, Any]:
    """Returns the config compose resolves for global_args, with every profile active and env files
    not inlined.

    Raises DockerError if compose cannot be run or its output cannot be read.
    """
    # '*' activates all profiles: `up svc` enables the profile of a named
    # service, which a plain `config` would leave out of the inspected set.
    # --no-env-resolution keeps env_file paths in the output instead of inlining
    # their contents, so the policy can see which files are read.
    cmd = [docker.binary, "compose", *global_args, "--profile", "*", "config", "--format", "json",
           "--no-env-resolution"]
    result = docker.capture(cmd)
    if result.returncode != 0:
        raise DockerError("docker compose config failed", result.stderr.strip())
    try:
        return json.loads(result.stdout)
    except ValueError as e:
        raise DockerError(f"cannot parse docker compose config output: {e}")


# compose labels each container with its project's name and the directory it was made from
PROJECT_LABEL = "com.docker.compose.project"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"


def made_from(name: str, docker: Docker) -> list[str]:
    """Returns the directories that the containers with the project name say they were made from, "" for
    one that does not say.

    Volumes and networks say nothing about where they came from, so only containers count. Raises
    DockerError if docker cannot say.
    """
    return docker.label_values(PROJECT_LABEL, name, WORKING_DIR_LABEL)


def name_lookup_failure(name: str, error: DockerError) -> Finding:
    """Returns the failure to look at the containers called by the project name (made_from).

    Parameters:
    - name: the project name
    - error: why docker could not say
    """
    return Finding.of(error, Verdict.FAILED).with_text(
        f"cannot tell whether another project is called {name!r}: {error}")


def name_conflicts(project_policy: policy.Policy, name: str, directory: str, docker: Docker) -> list[Finding]:
    """Checks the name of the project in directory against the containers that have it, by project_policy
    (Policy.check_project_name); returns what it finds, or the failure to look.

    Parameters:
    - project_policy: the policy to check with
    - name: the project name
    - directory: the project directory
    - docker: the docker to ask
    """
    try:
        found = made_from(name, docker)
    except DockerError as e:
        return [name_lookup_failure(name, e)]
    return project_policy.check_project_name(name, directory, found)


def names_project(args: Sequence[str], env: Mapping[str, str]) -> bool:
    """Tells whether the caller chose the project name, with -p or COMPOSE_PROJECT_NAME.

    Parameters:
    - args: the compose options before the subcommand, which select the project
    - env: the caller's environment
    """
    chosen = commandline.option_values(args, "--project-name", "-p")
    return bool(chosen or env.get("COMPOSE_PROJECT_NAME"))


def _project_location(args: Sequence[str], cwd: str, runtime: Runtime) -> ProjectLocation:
    """Determines the project directory as docker compose would from args and cwd.

    Raises DockerError if that cannot be done: a compose file from stdin, or as _find_compose_dir says.
    """
    env = runtime.env
    explicit = commandline.option_values(args, "--project-directory", None)
    if explicit:  # the last one wins, as in compose
        return ProjectLocation(os.path.realpath(os.path.join(cwd, explicit[-1])))

    files = commandline.option_values(args, "--file", "-f")
    if not files and env.get("COMPOSE_FILE"):
        files = env["COMPOSE_FILE"].split(env.get("COMPOSE_PATH_SEPARATOR", os.pathsep))
    if "-" in files:
        raise DockerError("a compose file read from stdin cannot be inspected")
    if files:  # compose takes the project directory from the first file
        return ProjectLocation(os.path.realpath(os.path.dirname(os.path.join(cwd, files[0]))))

    env_files = commandline.option_values(args, "--env-file", None)
    return _find_compose_dir(cwd, env_files, runtime.home, runtime.me[0])


def _find_compose_dir(start: str, env_files: Iterable[str], home: str, uid: int) -> ProjectLocation:
    """Finds the directory of the nearest compose file, walking up from start as compose does, with the .env
    files on the way (and the env_files entries) that could send compose elsewhere.

    The walk stops at home and at the first directory not owned by uid: a compose file found there was not
    put there for this project, and makes the location foreign. The starting directory is the caller's own
    choice and is not subject to the ownership rule. Raises DockerError if there is no compose file.
    """
    home = os.path.realpath(home)
    redirects = [path for path in (os.path.join(start, f) for f in env_files) if _sets_compose_vars(path)]
    directory = os.path.realpath(start)
    while True:
        has_file = any(os.path.exists(os.path.join(directory, n)) for n in COMPOSE_FILE_NAMES)
        if directory != os.path.realpath(start) and (directory == home or os.stat(directory).st_uid != uid):
            if has_file:
                return ProjectLocation(directory, foreign=True, redirects=tuple(redirects))
            raise DockerError("no compose file found")
        if _sets_compose_vars(env_file := os.path.join(directory, ".env")):
            redirects.append(env_file)
        if has_file:
            return ProjectLocation(directory, redirects=tuple(redirects))
        parent = os.path.dirname(directory)
        if parent == directory:
            raise DockerError("no compose file found")
        directory = parent


def _sets_compose_vars(path: str) -> bool:
    """Tells whether the .env file at path sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR.

    dockscreen does not read .env files, so such a setting would send compose to a different project
    directory than the one mounts are checked against. A file that cannot be read sets nothing.
    """
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return False
    return bool(COMPOSE_VARS_IN_ENV_FILE.search(content))
