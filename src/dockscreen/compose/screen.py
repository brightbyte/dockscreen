"""Inspect what docker compose is about to run, and apply the security policy."""

import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from dockscreen import commandline, config, messages, policy, verdict
from dockscreen.dockerclient import Docker, DockerError, DockerNotFound
from dockscreen.runtime import Runtime

COMPOSE_FILE_NAMES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")
COMPOSE_VARS_IN_ENV_FILE = re.compile(r"^\s*(export\s+)?COMPOSE_(FILE|PATH_SEPARATOR)\s*=", re.MULTILINE)
# A directory that equals or contains one of these must not be mounted wholesale.
SENSITIVE_DIRS = ("/", "/etc", "/usr", "/var", "/boot", "/root", "/run", "/proc", "/sys", "/dev")
DOCKER_SOCKET = "/var/run/docker.sock"


class ScreenError(Exception):
    """The project is refused before its config is looked at, or the config could not be inspected."""


class InspectError(ScreenError):
    """The config could not be inspected: no compose file, or compose could not read it."""


def inspect(global_args: Sequence[str], runtime: Runtime) -> tuple[dict[str, Any], str]:
    """Returns (config, project directory) for the project global_args select.

    Raises ScreenError if the project directory is, or contains, a sensitive path ($HOME, /etc, ...), since
    everything in it can be bind-mounted; InspectError if compose cannot give the config.
    """
    project_dir = _project_directory(global_args, runtime.cwd, runtime)
    found = _sensitive_inside(project_dir, runtime)
    if found:
        raise ScreenError(f"the project directory {project_dir} contains {found[0]}; "
                         "move the compose file into a directory of its own")
    return _load_config(global_args, runtime.docker), project_dir




def context(project_dir: str, runtime: Runtime, allow_me: bool = False,
            verified: Mapping[str, str] | None = None) -> policy.Context:
    """Builds the policy context for project_dir from the config file.

    allow_me: --allow-me was given, so the caller's own ids are allowed.
    Each service is checked with the settings of its image section, if one applies. Before the images are
    there, that is the section the image name points to; verified, once they are, maps each service to the
    section its image was proven to have been pulled for (config.section_for).
    """
    def settings_context(settings: config.Config) -> policy.Context:
        return policy.context_for(settings, project_dir, runtime.rules(allow_me), runtime.config_file)

    def scope(name: str, service: dict[str, Any]) -> policy.Context:
        if verified is None:
            repository = config.name_matches(runtime.settings, str(service.get("image") or ""),
                                             "build" in service)
        else:
            repository = verified.get(name)
        return settings_context(config.effective(runtime.settings, repository, project_dir))

    return settings_context(config.effective(runtime.settings, None, project_dir))._replace(scope=scope)


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
           rules: Callable[[dict[str, Any], policy.Context], list[str]] = policy.check_config) -> bool:
    """Tells whether rules(config, ctx) finds nothing in the selected project, printing the verdict."""
    try:
        config, project_dir = inspect(global_args, runtime)
    except InspectError as e:
        return verdict.screened([str(e)], failed=True)
    except ScreenError as e:
        return verdict.screened([str(e)])
    return verdict.screened(rules(config, context(project_dir, runtime)))


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
        raise InspectError(f"docker compose config failed:\n{result.stderr.strip()}")
    try:
        return json.loads(result.stdout)
    except ValueError as e:
        raise InspectError(f"cannot parse docker compose config output: {e}")


# compose labels each container with its project's name and the directory it was made from
PROJECT_LABEL = "com.docker.compose.project"
WORKING_DIR_LABEL = "com.docker.compose.project.working_dir"


def name_conflicts(name: str, directory: str, docker: Docker) -> list[str]:
    """Checks whether containers of a project called name exist that were made from another directory.

    Returns the problems, empty if there are none. The name is the project's own choice (`name:`, or
    `COMPOSE_PROJECT_NAME` in its `.env`), and it decides which volumes, networks and containers compose
    uses, replaces and, for `down -v`, removes. Volumes and networks alone say nothing about where they came
    from, so only containers count.
    """
    try:
        found = docker.label_values(PROJECT_LABEL, name, WORKING_DIR_LABEL)
    except DockerError as e:
        return [f"cannot tell whether another project is called {name!r}: {e}"]
    here = os.path.realpath(directory)
    # a container without the label cannot be shown to come from here
    others = sorted({path for path in found if not path or os.path.realpath(path) != here})
    if not others:
        return []
    shown = ", ".join(repr(path) if path else "an unknown directory" for path in others)
    return [messages.Reason(
        f"project name {name!r} is used by containers made from {shown}, not from {here}",
        "pass -p NAME to choose the name yourself")]


def names_project(global_args: Sequence[str], env: Mapping[str, str]) -> bool:
    """Tells whether the caller chose the project name, with -p or COMPOSE_PROJECT_NAME in env."""
    chosen = commandline.option_values(global_args, "--project-name", "-p")
    return bool(chosen or env.get("COMPOSE_PROJECT_NAME"))


def _project_directory(global_args: Sequence[str], cwd: str, runtime: Runtime) -> str:
    """Determines the project directory as docker compose would from global_args and cwd.

    Raises ScreenError if that cannot be checked (a compose file from stdin, or as _find_compose_dir says).
    """
    env = runtime.env
    explicit = commandline.option_values(global_args, "--project-directory", None)
    if explicit:
        return os.path.realpath(os.path.join(cwd, explicit[-1]))  # the last one wins, as in compose

    files = commandline.option_values(global_args, "--file", "-f")
    if not files and env.get("COMPOSE_FILE"):
        files = env["COMPOSE_FILE"].split(env.get("COMPOSE_PATH_SEPARATOR", os.pathsep))
    if "-" in files:
        raise ScreenError("a compose file read from stdin cannot be inspected")
    if files:  # compose takes the project directory from the first file
        return os.path.realpath(os.path.dirname(os.path.join(cwd, files[0])))

    env_files = commandline.option_values(global_args, "--env-file", None)
    return _find_compose_dir(cwd, env_files, runtime.home, runtime.me[0])


def _find_compose_dir(start: str, env_files: Iterable[str], home: str, uid: int) -> str:
    """Finds the directory of the nearest compose file, walking up from start as compose does.

    The walk stops at home and at the first directory not owned by uid: a compose file found there was not
    put there for this project, and raises ScreenError. The starting directory is the caller's own choice
    and is not subject to the ownership rule. Raises ScreenError if a .env (or an env_files entry) could
    send compose elsewhere, InspectError if there is no compose file.
    """
    home = os.path.realpath(home)
    for env_file in env_files:
        _refuse_compose_vars_in(os.path.join(start, env_file))
    directory = os.path.realpath(start)
    while True:
        has_file = any(os.path.exists(os.path.join(directory, n)) for n in COMPOSE_FILE_NAMES)
        if directory != os.path.realpath(start) and (directory == home or os.stat(directory).st_uid != uid):
            if has_file:
                raise ScreenError(f"the nearest compose file is in {directory}, which is your home directory "
                                 "or not yours; run from the project directory or use -f")
            raise InspectError("no compose file found")
        _refuse_compose_vars_in(os.path.join(directory, ".env"))
        if has_file:
            return directory
        parent = os.path.dirname(directory)
        if parent == directory:
            raise InspectError("no compose file found")
        directory = parent


def _refuse_compose_vars_in(path: str) -> None:
    """Raises ScreenError if the .env file at path sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR.

    dockscreen does not read .env files, so such a setting would send compose to a different project
    directory than the one mounts are checked against. A file that cannot be read is ignored.
    """
    try:
        with open(path) as f:
            content = f.read()
    except OSError:
        return
    if COMPOSE_VARS_IN_ENV_FILE.search(content):
        raise ScreenError(f"{path} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR; "
                         "set it in your shell or use -f, so the project directory can be verified")
