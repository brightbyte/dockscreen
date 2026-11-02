"""This module provides a project's config as docker compose resolves it, and what the policy judges about
the project before and around its config: where it is, what it is called, and which configured mount
directories are risky.
"""

import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from dockscreen.host import config
from dockscreen.host.dockerclient import Docker, DockerError, DockerNotFound
from dockscreen.host.runtime import Runtime
from dockscreen.model.location import Location
from dockscreen.model.project import Project
from dockscreen.screen import policy, verdict
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.scope import Scope
from dockscreen.util import commandline, messages

COMPOSE_FILE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
COMPOSE_VARS_IN_ENV_FILE = re.compile(r"^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=", re.MULTILINE)
# A directory that equals or contains one of these must not be mounted wholesale.
SENSITIVE_DIRS = ("/", "/etc", "/usr", "/var", "/boot", "/root", "/run", "/proc", "/sys", "/dev")
DOCKER_SOCKET = "/var/run/docker.sock"


class Refused(Exception):
    """Refusal of a project before its config is looked at, with the policy's findings."""

    def __init__(self, findings: Sequence[Finding]) -> None:
        super().__init__("; ".join(findings))
        self.findings = list(findings)


class InspectError(Exception):
    """Failure to inspect a project's config: no compose file, one that cannot be looked at, or compose
    could not read it; with what compose printed about it (output), if anything.
    """

    def __init__(self, message: str, output: str | None = None) -> None:
        super().__init__(message)
        self.output = output or None


def project(global_args: Sequence[str], runtime: Runtime) -> Project:
    """Returns the project global_args select, with its definition as compose resolves it.

    Raises Refused if the policy refuses where the project is (Policy.check_location); InspectError if
    compose cannot give the definition.
    """
    location = locate(global_args, runtime)
    refusals = Scope(runtime, project_dir=location.directory).project_policy().check_location(location)
    if refusals:
        raise Refused(refusals)
    return Project(_load_config(global_args, runtime.docker), location)


def locate(global_args: Sequence[str], runtime: Runtime) -> Location:
    """Returns where the project global_args select is, as compose would find it.

    Raises InspectError if that cannot be found: the compose file is read from stdin, or there is none.
    """
    location = _project_location(global_args, runtime.cwd, runtime)
    return location._replace(sensitive=tuple(_sensitive_inside(location.directory, runtime)))


def _sensitive_paths(runtime: Runtime) -> list[str]:
    """Returns the paths whose directories must not be mountable: system directories, the home
    directory, the config files and the docker socket.
    """
    return [*SENSITIVE_DIRS, runtime.home, config.SYSTEM_FILE, runtime.config_file, DOCKER_SOCKET]


def _sensitive_inside(directory: str, runtime: Runtime) -> list[str]:
    """Returns the sensitive paths that directory equals or contains, with symlinks resolved."""
    root = os.path.realpath(directory)
    return [path for path in _sensitive_paths(runtime) if policy.is_inside(os.path.realpath(path), root)]


def mount_dir_warnings(runtime: Runtime) -> list[messages.Marked]:
    """Returns one warning per configured mount dir that equals or contains a sensitive path."""
    return [
        messages.Marked(
            messages.WARN,
            f"the configured mount dir {directory} contains {found[0]}, so containers can mount it",
            "narrow mount_dirs in the config file")
        for directory in config.all_mount_dirs(runtime.settings)
        if (found := _sensitive_inside(directory, runtime))
    ]


def passes(global_args: Sequence[str], runtime: Runtime,
           rules: Callable[[policy.Policy, Project], list[Finding]] = policy.Policy.check_project) -> bool:
    """Tells whether rules(policy, project) finds nothing in the selected project, printing the verdict."""
    try:
        found = project(global_args, runtime)
    except InspectError as e:
        return verdict.screened(Report.failure(e))
    except Refused as e:
        return verdict.screened(Report.of(e.findings))
    project_policy = Scope(runtime, project_dir=found.directory).project_policy()
    return verdict.screened(Report.of(rules(project_policy, found)))


def _load_config(global_args: Sequence[str], docker: Docker) -> dict[str, Any]:
    """Returns the config compose resolves for global_args, with every profile active and env files
    not inlined.

    Raises InspectError if compose cannot be run or its output cannot be read.
    """
    # '*' activates all profiles: `up svc` enables the profile of a named
    # service, which a plain `config` would leave out of the inspected set.
    # --no-env-resolution keeps env_file paths in the output instead of inlining
    # their contents, so the policy can see which files are read.
    cmd = [docker.binary, "compose", *global_args, "--profile", "*", "config", "--format", "json",
           "--no-env-resolution"]
    try:
        result = docker.capture(cmd)
    except DockerNotFound:
        raise InspectError("'docker' not found in PATH")
    if result.returncode != 0:
        raise InspectError("docker compose config failed", result.stderr.strip())
    try:
        return json.loads(result.stdout)
    except ValueError as e:
        raise InspectError(f"cannot parse docker compose config output: {e}")


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
    """Returns the failure to look at the containers called by the project name (made_from)."""
    return Finding(f"cannot tell whether another project is called {name!r}: {error}", Severity.FAILED,
                   output=error.output)


def name_conflicts(project_policy: policy.Policy, name: str, directory: str, docker: Docker) -> list[Finding]:
    """Checks the name of the project in directory against the containers that have it, by project_policy
    (Policy.check_project_name); returns what it finds, or the failure to look.
    """
    try:
        found = made_from(name, docker)
    except DockerError as e:
        return [name_lookup_failure(name, e)]
    return project_policy.check_project_name(name, directory, found)


def names_project(global_args: Sequence[str], env: Mapping[str, str]) -> bool:
    """Tells whether the caller chose the project name, with -p or COMPOSE_PROJECT_NAME in env."""
    chosen = commandline.option_values(global_args, "--project-name", "-p")
    return bool(chosen or env.get("COMPOSE_PROJECT_NAME"))


def _project_location(global_args: Sequence[str], cwd: str, runtime: Runtime) -> Location:
    """Determines the project directory as docker compose would from global_args and cwd.

    Raises InspectError if that cannot be done: a compose file from stdin, or as _find_compose_dir says.
    """
    env = runtime.env
    explicit = commandline.option_values(global_args, "--project-directory", None)
    if explicit:  # the last one wins, as in compose
        return Location(os.path.realpath(os.path.join(cwd, explicit[-1])))

    files = commandline.option_values(global_args, "--file", "-f")
    if not files and env.get("COMPOSE_FILE"):
        files = env["COMPOSE_FILE"].split(env.get("COMPOSE_PATH_SEPARATOR", os.pathsep))
    if "-" in files:
        raise InspectError("a compose file read from stdin cannot be inspected")
    if files:  # compose takes the project directory from the first file
        return Location(os.path.realpath(os.path.dirname(os.path.join(cwd, files[0]))))

    env_files = commandline.option_values(global_args, "--env-file", None)
    return _find_compose_dir(cwd, env_files, runtime.home, runtime.me[0])


def _find_compose_dir(start: str, env_files: Iterable[str], home: str, uid: int) -> Location:
    """Finds the directory of the nearest compose file, walking up from start as compose does, with the .env
    files on the way (and the env_files entries) that could send compose elsewhere.

    The walk stops at home and at the first directory not owned by uid: a compose file found there was not
    put there for this project, and makes the location foreign. The starting directory is the caller's own
    choice and is not subject to the ownership rule. Raises InspectError if there is no compose file.
    """
    home = os.path.realpath(home)
    redirects = [path for path in (os.path.join(start, f) for f in env_files) if _sets_compose_vars(path)]
    directory = os.path.realpath(start)
    while True:
        has_file = any(os.path.exists(os.path.join(directory, n)) for n in COMPOSE_FILE_NAMES)
        if directory != os.path.realpath(start) and (directory == home or os.stat(directory).st_uid != uid):
            if has_file:
                return Location(directory, foreign=True, redirects=tuple(redirects))
            raise InspectError("no compose file found")
        if _sets_compose_vars(env_file := os.path.join(directory, ".env")):
            redirects.append(env_file)
        if has_file:
            return Location(directory, redirects=tuple(redirects))
        parent = os.path.dirname(directory)
        if parent == directory:
            raise InspectError("no compose file found")
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
