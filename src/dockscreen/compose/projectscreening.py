"""This module provides functions for screening a compose project in stages, and for running docker compose
from the config that was checked, not from the files compose would find itself.

Each stage is a function from what the one before it gave to what the next needs, or to the report that
stops screening: the loaded project (load_project, Loaded) is checked before any image is looked at
(check), which clears it (Cleared); its images are then acquired and decided on (decide), and the project
with what was decided is checked once more (finish), which makes it runnable (Runnable). A caller composes
the stages it needs; the types say which stage may follow which, so nothing is pulled or built for a project
that was not cleared, and nothing runs that was not checked last.

The resolved config is hardened, checked, written to a private temporary file
(`config` prints a literal `$` as `$$`, so compose reads the file back to the same values)
and handed to compose as its only file, together with the project directory and
name it came from. What was checked is then exactly what runs: no second
reading of the project's files, no discovery rules to mirror. Before any image is
pulled or built, compose is asked for the config of the generated file, which is
refused if it differs from what was checked (decide). The price is that
compose runs as a child process (so the file can be removed afterwards) and
shows the temporary file as its config file.
"""

import contextlib
import itertools
import json
import os
import tempfile
from collections.abc import Callable, Iterator, Sequence
from typing import Any, NamedTuple, Self

from dockscreen.cli import userargs
from dockscreen.compose import inspect, runoptions, serviceinfo
from dockscreen.host import shellenv
from dockscreen.host.dockerclient import Docker, DockerError, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import STRICT, TRUSTED, Origin
from dockscreen.model.project import Project
from dockscreen.screen import hardening, policy, substitutions, verdict
from dockscreen.screen.decisions import Decisions
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.screener import Screener
from dockscreen.screen.substitutions import Substitution
from dockscreen.util import commandline, messages

# Options that select the files and the project; ours replace them.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")

# Writes a config to a generated file and returns the compose command line on it (generated).
Command = Callable[[dict[str, Any]], list[str]]


class Loaded(NamedTuple):
    """Record of a compose project as screening starts from it, for the first stage (check). It holds the
    options that select the project, the project as compose resolved it, whether its daemon may be another
    host's, and the substitutions that add the defaults to it.

    What runs is the resolved project with every substitution made, in order: the hardening, then what the
    images decided (finish). Nothing else changes the definition that compose gets. Instances come from
    load_project.

    Attributes:
    - global_args: the compose options that select the project
    - resolved: the project as compose resolved it
    - remote: whether its daemon may not be this host's
    - hardening: the substitutions that add the defaults (Substitution)
    """
    global_args: tuple[str, ...]
    resolved: Project
    remote: bool
    hardening: tuple[Substitution, ...]

    @property
    def hardened(self) -> Project:
        """Returns the project with the defaults added, which is what the images are acquired for."""
        return substitutions.applied(self.resolved, self.hardening)

    @property
    def directory(self) -> str:
        """Returns the project directory."""
        return self.resolved.directory

    def static(self) -> Project:
        """Returns the hardened project as the checks before any image is looked at see it, which leave the
        users that the images decide to later.
        """
        hardened = self.hardened
        unset = hardened.services_without_user
        return hardened.with_origins({name: {"user": Origin.IMAGE} for name in unset})

    def with_hardened(self, definition: dict[str, Any]) -> Self:
        """Returns this project with definition as its resolved one.

        Parameters:
        - definition: a definition with the defaults already added, as hardened has it
        """
        return self._replace(resolved=self.hardened.with_definition(definition), hardening=())

    def generated(self, docker_binary: str) -> contextlib.AbstractContextManager[Command]:
        """Returns _generated() for this project."""
        return _generated(self.global_args, self.directory, docker_binary)


class Cleared(NamedTuple):
    """Record of a loaded project that passed the checks before any image is looked at, which is what
    acquiring its images needs (decide). It holds the project.

    Instances come from check.

    Attributes:
    - loaded: the project (Loaded)
    """
    loaded: Loaded


class Runnable(NamedTuple):
    """Record of a project that passed every stage of screening, which is what may run. It holds the project
    that will run, what was decided about its images, and what the last check found.

    Instances come from finish.

    Attributes:
    - project: the project that will run
    - decided: the Decisions about its images
    - report: what the check of the project that will run found
    """
    project: Project
    decided: Decisions
    report: Report


def load_project(global_args: Sequence[str], runtime: Runtime) -> Loaded:
    """Loads the project global_args select, with the defaults to add.

    Raises inspect.Refused if the policy refuses where it is, DockerError if it cannot be inspected,
    ValueError if it cannot be hardened.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    """
    found = inspect.project(global_args, runtime)
    remote = is_remote(global_args, runtime.docker)
    changes = hardening.changes(found.definition, runtime.accounts)
    return Loaded(tuple(global_args), found, remote, tuple(changes))


def check(loaded: Loaded, screener: Screener) -> Cleared | Report:
    """Checks the project before any image is looked at (Loaded.static): its definition, its daemon, and,
    once those pass, the containers that already have its name.

    Returns the project cleared for acquiring its images, or the report that stops it.
    """
    static_policy = screener.project_policy(loaded.resolved)
    found = Report.of([*static_policy.check_project(loaded.static()),
                       *static_policy.check_daemon(loaded.remote)])
    if found.passed:  # asking docker about the name is left until nothing else stands in the way
        found = Report.of([*found.findings, *_name_conflicts(loaded, static_policy, screener)])
    return Cleared(loaded) if found.passed else found


def decide(cleared: Cleared, screener: Screener, command: Command, args: Sequence[str] = (),
           chosen: frozenset[str] = frozenset()) -> Decisions:
    """Finds out what screening needs to know about the services of the hardened project (serviceinfo.prepare)
    and decides their users (Screener.decide), once compose has been shown to read the generated file back as
    its definition.

    Returns failed Decisions, with nothing pulled or built, if compose reads it differently.

    Parameters:
    - cleared: the project, as check cleared it
    - screener: the Screener to pull, build, look and decide with
    - command: writes the generated file (generated())
    - args, chosen: as serviceinfo.prepare takes them
    """
    project = cleared.loaded.hardened
    on_file = command(project.definition)
    problem = _read_back_problem(on_file, project.definition, screener.docker)
    if problem:
        return screener.decide(project, None, [Finding(problem, Severity.FAILED)])
    images, failures = serviceinfo.prepare(on_file, project, list(args), screener, chosen)
    return screener.decide(project, images, failures)


def finish(cleared: Cleared, decided: Decisions, screener: Screener, parsed: userargs.Parsed | None = None,
           strict: bool = False) -> Runnable | Report:
    """Makes the project that will run, the resolved one with the hardening and then what the images decided
    (Decisions.changes), and checks it with the policy that decided, with image sections only where the
    images proved them.

    Returns it as runnable, or the report that stops it, which is decided's if that did not pass.

    Parameters:
    - cleared: the project, as check cleared it
    - decided: what decide decided about its images
    - screener: the Screener of the command
    - parsed: the arguments of the subcommand, with the user the command line chose (compose_run)
    - strict: --strict-screen was given, so the service as `run`'s options change it (runoptions) is judged,
      with the command line untrusted; otherwise those options are taken as given, as for `docker run`
    """
    if not decided.report.passed:
        return decided.report
    loaded = cleared.loaded
    final = substitutions.applied(loaded.resolved, [*loaded.hardening, *decided.changes])
    judged, trust = (final, TRUSTED)
    if strict and parsed:
        judged, trust = _as_run(final, parsed, screener.runtime), STRICT
    checked = Report.of(decided.policy.with_trust(trust).check_project(judged))
    return Runnable(final, decided, checked) if checked.passed else checked


def surroundings(loaded: Loaded, screener: Screener) -> list[Finding]:
    """Returns what the policy finds in what the project gets from around it: configured mount dirs that
    contain sensitive paths (Policy.check_mount_dirs), and variables its services take from the shell
    (Policy.check_shell_env).
    """
    runtime, here = screener.runtime, screener.policy(loaded.directory)
    return [*here.check_mount_dirs(inspect.sensitive_mount_dirs(runtime)),
            *here.check_shell_env(shellenv.copied(loaded.hardened.definition, runtime.env))]


def check_and_run(global_args: list[str], sub: str, parsed: userargs.Parsed, runtime: Runtime,
                  allow_me: bool = False, strict: bool = False) -> int:
    """Runs `docker compose global_args sub` with parsed's arguments, sub a subcommand that starts
    containers, on the project global_args select if it passes the checks.

    Returns the exit status: 1 if the project or its images are refused or cannot be checked, else the
    subcommand's. The images of services that set no user are acquired first, by the project's pull policy,
    and decided on (serviceinfo, imageusers); the config that runs is the one that was checked, with the
    result.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - sub: the subcommand
    - parsed: the subcommand's arguments, with the user the command line chose (compose_run)
    - runtime: the Runtime of the command
    - allow_me: --allow-me was given, so the caller's own ids are allowed
    - strict: --strict-screen was given, so the service as `run`'s options change it (runoptions) is judged,
      with the command line untrusted; otherwise those options are taken as given, as for `docker run`
    """
    try:
        loaded = load_project(global_args, runtime)
    except DockerError as e:
        verdict.screened(Report.failure(e))
        return 1
    except inspect.Refused as e:
        verdict.screened(Report.of(e.findings))
        return 1
    except ValueError as e:
        verdict.screened(Report.refusal(str(e)))
        return 1

    screener = Screener(runtime, allow_me)
    lines = [*parsed.users.notices, *surroundings(loaded, screener),
             verdict.root_default_notice(screener.policy(loaded.directory).default_user),
             *substitutions.describe(loaded.hardening)]
    cleared = check(loaded, screener)
    if isinstance(cleared, Report):
        verdict.screened(cleared)
        return 1
    with loaded.generated(screener.docker.binary) as command:
        decided = decide(cleared, screener, command, parsed.args, _chosen(parsed))
        runnable = finish(cleared, decided, screener, parsed, strict)
        if isinstance(runnable, Report):
            verdict.screened(runnable)
            return 1
        for line in [*lines, *decided.notices()]:
            if line:
                messages.notice(line)
        verdict.screened(runnable.report)
        return screener.docker.run_child([*command(runnable.project.definition), sub, *parsed.args])


def _name_conflicts(loaded: Loaded, static_policy: policy.Policy, screener: Screener) -> list[Finding]:
    """Returns what static_policy finds in the containers that have the project's name, or the failure to
    look (inspect.name_conflicts).

    Not looked at for a name the caller chose, or on a daemon that may not be this host's.
    """
    name = loaded.resolved.name
    if not name or loaded.remote or inspect.names_project(loaded.global_args, screener.runtime.env):
        return []
    return inspect.name_conflicts(static_policy, name, loaded.directory, screener.docker)


def _as_run(final: Project, parsed: userargs.Parsed, runtime: Runtime) -> Project:
    """Returns the final project with the service that `run` runs changed by its options (runoptions)."""
    name = parsed.service
    if name is None or name not in (final.definition.get("services") or {}):
        return final  # compose refuses to run it
    return substitutions.applied(final, runoptions.substitutions(parsed, final.service(name), runtime))


def _chosen(parsed: userargs.Parsed) -> frozenset[str]:
    """Returns the services whose user the command line chooses: `run -u uid:gid` or `run --as NAME`."""
    return frozenset({parsed.service}) if parsed.users.chosen and parsed.service else frozenset()


@contextlib.contextmanager
def _generated(global_args: Sequence[str], project_dir: str,
               docker_binary: str) -> Iterator[Command]:
    """Provides a private temporary directory for generated configs, and yields command(config).

    command writes config there and returns the `docker compose` command line on it alone, with the project
    directory and name pinned, ready for a subcommand to be appended. Everything is removed afterwards.
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
    """Returns why compose does not read the generated file back as exactly config, or None if it does.

    A value compose reads differently would run differently from what the policy saw.
    command: the compose command line on the generated file.
    """
    result = docker.capture(
        [*command, "--profile", "*", "config", "--format", "json", "--no-env-resolution"])
    try:
        resolved = json.loads(result.stdout) if result.returncode == 0 else None
    except ValueError:
        resolved = None
    if resolved is None:
        return "docker compose could not read back the config that was checked"
    where = _first_difference(config, resolved)
    if where:
        return f"docker compose reads the checked config differently at {where}; not running it"
    return None


def _first_difference(expected: Any, actual: Any, path: str = "config") -> str | None:
    """Returns the path at which two JSON values first differ, or None if they are equal."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual), key=str):
            if key not in expected or key not in actual:
                return f"{path}.{key}"
            if where := _first_difference(expected[key], actual[key], f"{path}.{key}"):
                return where
        return None
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        for i, (e, a) in enumerate(zip(expected, actual)):
            if where := _first_difference(e, a, f"{path}[{i}]"):
                return where
        return None
    # True == 1 and 1 == 1.0 in Python, but not to compose
    return None if expected == actual and type(expected) is type(actual) else path
