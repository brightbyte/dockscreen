"""This module provides functions for screening a compose project in stages, and for running docker compose
from the config that was checked, not from the files compose would find itself.

Each stage is a function. It takes what the stage before it gave, and returns what the next stage needs,
or the report that stops screening. The function check judges the loaded project (load_project,
LoadedProject) before dockscreen looks at any image, and clears it (ClearedProject). The function decide
then acquires the project's images and decides about them. The function finish checks the project with
those decisions once more, and makes it runnable (RunnableProject). A caller composes the stages it
needs. The types say which stage may follow which, so dockscreen pulls or builds nothing for a project
that the policy did not clear, and runs nothing that the policy did not check last.

Commands that act on a project's existing containers check only its name (check_name). Commands that
only build check only what the builds can reach (check_build).

Projects need screening because `docker compose up` gives a project every power the daemon has, which is
root on this host, and a project is a directory that someone else wrote. The stages exist for these reasons:
- load_project: dockscreen asks compose for its own reading of the project (`config`), since a second
  parser would read the YAML, the interpolation and the merging of files differently; it locates the
  project directory first, because the policy judges bind mounts against it.
- check: the policy judges the definition's requests before dockscreen pulls or builds anything, because
  building runs the project's Dockerfile, and a refused project should not get even that far.
- decide: a service without `user:` runs as the user its image chooses, and only the image can tell which
  user that is. dockscreen acquires the image as compose would, then looks at it without starting it.
- finish: the defaults, the decided users and the pinned images change the project, so the policy judges
  the result once more, as the project that will run.
- running from the generated file: if compose read the project's own files again, it could see something
  else (a file changed in between, discovery rules, interpolation). So compose reads only the file the
  policy checked. dockscreen has compose read that file back first, in case compose would interpret it
  differently.
- check_name: the project name decides which existing volumes, networks and containers compose acts on,
  so a project that claims another's name reaches that project's data.
- check_build: a build reads files from this host and runs the project's Dockerfile.

dockscreen hardens the resolved config, has the policy check it, writes it to a private temporary file
(`config` prints a literal `$` as `$$`, so compose reads the file back to the same values) and hands it to
compose as its only file, together with the project directory and name it came from. The checked config
is then exactly the one that runs: compose does not read the project's files a second time, and there are
no discovery rules to mirror. Before it pulls or builds any image, dockscreen asks compose for the config of
the generated file, and refuses the run if that config differs from the checked config (decide). The price is
that compose runs as a child process (so that dockscreen can remove the file afterwards) and shows the
temporary file as its config file.
"""

import contextlib
import itertools
import json
import os
import tempfile
from collections.abc import Callable, Iterator, Sequence
from typing import Any, NamedTuple, Self

from dockscreen.host import shellenv
from dockscreen.host.docker import Docker, DockerError, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import STRICT_ORIGINS, TRUSTED_ORIGINS, Origin
from dockscreen.model.project import Project
from dockscreen.policy import finding, hardening, policy
from dockscreen.policy.decisions import Decisions
from dockscreen.policy.finding import Finding, Verdict
from dockscreen.policy.notice import Notice
from dockscreen.policy.projectpatch import ProjectPatch
from dockscreen.policy.report import Report
from dockscreen.screen import inspect, runoptions, serviceinfo, userargs
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline

# Options that select the files and the project; ours replace them. Left in, a second -f would add a file
# that was never checked, and another directory or name would make compose resolve paths, or act on
# containers, other than those checked.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")

# Writes a config to a generated file and returns the compose command line that reads it (generated_files).
Command = Callable[[dict[str, Any]], list[str]]


class LoadedProject(NamedTuple):
    """Record of a compose project as screening starts from it, for the first stage (check). It holds the
    options that select the project, the project as compose resolved it, whether its daemon may be another
    host's, and the substitutions that add the defaults to it.

    The project that runs is the resolved project with every substitution made, in order: first the
    hardening, then the substitutions that follow from the images (finish). Nothing else changes the
    definition that compose gets. Instances come from load_project.

    Attributes:
    - global_args: the compose options that select the project
    - resolved_project: the project as compose resolved it
    - is_remote: whether its daemon may not be this host's
    - hardening: the patch that adds the defaults
    """
    global_args: tuple[str, ...]
    resolved_project: Project
    is_remote: bool
    hardening: ProjectPatch

    @property
    def hardened_project(self) -> Project:
        """Returns the project with the defaults added. dockscreen acquires the images for this project."""
        return self.hardening.apply_to(self.resolved_project)

    @property
    def directory(self) -> str:
        """Returns the project directory."""
        return self.resolved_project.directory

    def static_project(self) -> Project:
        """Returns the hardened project as the checks before any image see it. Those checks leave the users
        that the images decide to a later stage.
        """
        hardened_project = self.hardened_project
        services_without_user = hardened_project.services_without_user
        return hardened_project.with_origins({name: {"user": Origin.IMAGE} for name in services_without_user})

    def with_hardened_definition(self, definition: dict[str, Any]) -> Self:
        """Returns this project with definition as its resolved one.

        Parameters:
        - definition: a definition with the defaults already added, as hardened_project has it
        """
        return self._replace(resolved_project=self.hardened_project.with_definition(definition),
                             hardening=ProjectPatch())

    def generated_files(self, docker_binary: str) -> contextlib.AbstractContextManager[Command]:
        """Returns _generated_files() for this project."""
        return _generated_files(self.global_args, self.directory, docker_binary)


class ClearedProject(NamedTuple):
    """Record of a loaded project that passed the checks made before dockscreen looks at any image.
    The stage decide, which acquires the images, needs such a record. It holds the project.

    Instances come from the function check.

    Attributes:
    - loaded_project: the project (LoadedProject)
    """
    loaded_project: LoadedProject


class RunnableProject(NamedTuple):
    """Record of a project that passed every stage of screening, which is what may run. It holds the project
    that will run, what was decided about its images, and what the last check found.

    Instances come from the function finish.

    Attributes:
    - project: the project that will run
    - decisions: the Decisions about its images
    - report: what the check of the project that will run found
    """
    project: Project
    decisions: Decisions
    report: Report


def load_project(args: Sequence[str], runtime: Runtime) -> LoadedProject:
    """Loads the project that args select, with the defaults to add.

    Raises inspect.ProjectRefusal if the policy refuses the project's location, raises DockerError if docker
    cannot inspect the project, and raises ValueError if the project cannot be hardened.

    Parameters:
    - args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    """
    inspected_project = inspect.project(args, runtime)
    is_remote_daemon = is_remote(args, runtime.docker)
    hardening_patch = hardening.changes(inspected_project.definition,
                                        Screener(runtime).policy(inspected_project.directory))
    return LoadedProject(tuple(args), inspected_project, is_remote_daemon, hardening_patch)


def check(loaded_project: LoadedProject, screener: Screener) -> ClearedProject | Report:
    """Checks the project as it is before dockscreen looks at any image (LoadedProject.static_project). It
    checks the definition and the daemon and, once those pass, the containers that already have the
    project's name.

    Returns the project cleared for acquiring its images, or the report that stops it.
    """
    static_policy = screener.project_policy(loaded_project.resolved_project)
    static_report = Report.of([*static_policy.check_project(loaded_project.static_project()),
                               *static_policy.check_daemon(loaded_project.is_remote)])
    if static_report.has_passed:  # asking docker about the name is left until nothing else stands in the way
        conflicts = _name_conflicts(loaded_project, static_policy, screener)
        static_report = static_report.with_more_findings(conflicts)
    return ClearedProject(loaded_project) if static_report.has_passed else static_report


def decide(cleared_project: ClearedProject, screener: Screener, command: Command, args: Sequence[str] = (),
           chosen_services: frozenset[str] = frozenset()) -> Decisions:
    """Finds out what screening needs to know about the services of the hardened project
    (serviceinfo.prepare), and decides their users (Screener.decide). It does this only after compose has
    read the generated file back as the project's definition.

    If compose reads the file differently, this returns failed Decisions, and pulls or builds nothing.

    Parameters:
    - cleared_project: the project, as the function check cleared it
    - screener: the Screener to pull, build, look and decide with
    - command: writes the generated file (generated_files())
    - args, chosen_services: as serviceinfo.prepare takes them
    """
    project = cleared_project.loaded_project.hardened_project
    compose_command = command(project.definition)
    read_back_problem = _read_back_problem(compose_command, project.definition, screener.docker)
    if read_back_problem:
        return screener.decide(project, None, [Finding(read_back_problem, Verdict.FAILED)])
    service_images, failures = serviceinfo.prepare(compose_command, project, list(args), screener,
                                                   chosen_services)
    return screener.decide(project, service_images, failures)


def finish(cleared_project: ClearedProject, decisions: Decisions, screener: Screener,
           user_args: userargs.UserArgs[str] | None = None, is_strict: bool = False
           ) -> RunnableProject | Report:
    """Makes the project that will run, and checks it. The project that will run is the resolved project
    with the hardening added, and then with the changes that follow from the images (Decisions.changes). The
    policy that made the decisions checks it, with image sections only where the images proved them.

    Returns the project as runnable, or the report that stops it. That report is the report of decisions,
    if decisions did not pass.

    Parameters:
    - cleared_project: the project, as the function check cleared it
    - decisions: the decisions that the function decide made about its images
    - screener: the Screener of the command
    - user_args: the arguments of the subcommand, with the user the command line chose (compose_run)
    - is_strict: --strict-screen was given. The policy then judges the service as `run`'s options change it
      (runoptions), and does not trust the command line. Otherwise compose gets those options as given, as
      for `docker run`.
    """
    if not decisions.report.has_passed:
        return decisions.report
    loaded_project = cleared_project.loaded_project
    final_project = (loaded_project.hardening + decisions.changes).apply_to(loaded_project.resolved_project)
    judged_project, trust = (final_project, TRUSTED_ORIGINS)
    if is_strict and user_args:
        judged_project, trust = _as_run(final_project, user_args, screener.runtime), STRICT_ORIGINS
    final_report = Report.of(decisions.policy.with_trust(trust).check_project(judged_project))
    if not final_report.has_passed:
        return final_report
    return RunnableProject(final_project, decisions, final_report)


def surroundings(loaded_project: LoadedProject, screener: Screener) -> list[Notice]:
    """Returns the policy's findings about what the project takes from its surroundings: configured mount
    dirs that contain sensitive paths (Policy.check_mount_dirs), and variables that its services take from
    the shell (Policy.check_shell_env).
    """
    runtime, project_policy = screener.runtime, screener.policy(loaded_project.directory)
    sensitive_mount_dirs = inspect.sensitive_mount_dirs(runtime)
    copied_variables = shellenv.copied_shell_variables(loaded_project.hardened_project.definition,
                                                       runtime.env)
    return [*project_policy.check_mount_dirs(sensitive_mount_dirs),
            *project_policy.check_shell_env(copied_variables)]


def check_name(global_args: Sequence[str], runtime: Runtime) -> list[Finding]:
    """Returns the findings that forbid the project its name: containers made from another directory have
    the same name.

    The list is empty for a name that the user chose on the command line or in the environment. It is also
    empty for a project that docker cannot inspect; compose reports that itself.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    """
    if inspect.names_project(global_args, runtime.env):
        return []
    try:
        project = inspect.project(global_args, runtime)
    except (inspect.ProjectRefusal, DockerError):
        # these commands start nothing and build nothing, so compose may as well say what is wrong
        return []
    if not project.name:
        return []
    project_policy = Screener(runtime).project_policy(project)
    return inspect.name_conflicts(project_policy, project.name, project.directory, runtime.docker)


def check_build(global_args: Sequence[str], runtime: Runtime) -> list[Finding]:
    """Returns the findings that stop the project's builds: what the builds can reach
    (Policy.check_project_build), or the reason the project could not be loaded or was refused first.

    Unlike check_name, this does not leave a project that cannot be loaded to compose: a build reads files,
    so a build that the policy cannot check does not run.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    """
    try:
        project = inspect.project(global_args, runtime)
    except DockerError as e:
        return [finding.failure_of(e)]
    except inspect.ProjectRefusal as e:
        return list(e.findings)
    return Screener(runtime).project_policy(project).check_project_build(project)


def _name_conflicts(loaded_project: LoadedProject, static_policy: policy.Policy,
                    screener: Screener) -> list[Finding]:
    """Returns static_policy's findings about the containers that have the project's name, or the failure to
    look at them (inspect.name_conflicts).

    This looks at nothing for a name that the user chose, or on a daemon that may not be this host's.
    """
    name = loaded_project.resolved_project.name
    is_name_chosen = inspect.names_project(loaded_project.global_args, screener.runtime.env)
    if not name or loaded_project.is_remote or is_name_chosen:
        return []
    return inspect.name_conflicts(static_policy, name, loaded_project.directory, screener.docker)


def _as_run(final_project: Project, user_args: userargs.UserArgs[str], runtime: Runtime) -> Project:
    """Returns the final project with the service that `run` runs changed by its options (runoptions)."""
    name = user_args.service
    if name is None or name not in (final_project.definition.get("services") or {}):
        return final_project  # compose refuses to run it
    return runoptions.substitutions(user_args, final_project.service(name), runtime).apply_to(final_project)


@contextlib.contextmanager
def _generated_files(global_args: Sequence[str], project_dir: str,
                     docker_binary: str) -> Iterator[Command]:
    """Provides a private temporary directory for generated configs, and yields command(config).

    The function command writes config there, and returns a `docker compose` command line that reads only that
    file. The command line pins the project directory and name, and is ready for a subcommand to be appended.
    This removes the directory and its files afterwards.

    This creates the directory for this run, readable by the user only, so another user of this host
    can neither read the config nor put a file of their own in its place for compose to read. It passes
    the project directory and name, rather than leave compose to work them out from the file's location.
    The file is in the temporary directory, but compose resolved its relative paths against the project
    directory.
    """
    counter = itertools.count()
    with tempfile.TemporaryDirectory(prefix="dockscreen-") as directory:
        def command(config: dict[str, Any]) -> list[str]:
            path = os.path.join(directory, f"compose-{next(counter)}.yaml")
            # 0600: the config can hold secrets; O_EXCL: never write through a file or link already there
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump(config, f)  # JSON is YAML
            return [
                docker_binary, "compose", *commandline.strip_options(global_args, REPLACED_OPTIONS),
                "-f", path, "--project-directory", project_dir, "--project-name", config["name"],
            ]
        yield command


def _read_back_problem(command: Sequence[str], config: dict[str, Any], docker: Docker) -> str | None:
    """Returns the reason compose does not read the generated file back as exactly config, or None if it
    does.

    A value compose reads differently would run differently from what the policy saw.
    command: the compose command line on the generated file.
    """
    result = docker.capture(
        [*command, "--profile", "*", "config", "--format", "json", "--no-env-resolution"])
    try:
        read_back_config = json.loads(result.stdout) if result.returncode == 0 else None
    except ValueError:
        read_back_config = None
    if read_back_config is None:
        return "docker compose could not read back the config that was checked"
    difference_path = _first_difference(config, read_back_config)
    if difference_path:
        return f"docker compose reads the checked config differently at {difference_path}; not running it"
    return None


def _first_difference(expected_value: Any, actual_value: Any, path: str = "config") -> str | None:
    """Returns the path at which two JSON values first differ, or None if they are equal."""
    if isinstance(expected_value, dict) and isinstance(actual_value, dict):
        for key in sorted(set(expected_value) | set(actual_value), key=str):
            if key not in expected_value or key not in actual_value:
                return f"{path}.{key}"
            if difference_path := _first_difference(expected_value[key], actual_value[key], f"{path}.{key}"):
                return difference_path
        return None
    if (isinstance(expected_value, list) and isinstance(actual_value, list)
            and len(expected_value) == len(actual_value)):
        for i, (e, a) in enumerate(zip(expected_value, actual_value)):
            if difference_path := _first_difference(e, a, f"{path}[{i}]"):
                return difference_path
        return None
    # True == 1 and 1 == 1.0 in Python, but not to compose
    return None if expected_value == actual_value and type(expected_value) is type(actual_value) else path
