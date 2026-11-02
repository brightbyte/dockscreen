"""This module provides a compose project as dockscreen checks it, and runs docker compose from the config
that was checked, not from the files compose would find itself.

The resolved config is hardened, checked, written to a private temporary file
(`config` prints a literal `$` as `$$`, so compose reads the file back to the same values)
and handed to compose as its only file, together with the project directory and
name it came from. What was checked is then exactly what runs: no second
reading of the project's files, no discovery rules to mirror. Before any image is
pulled or built, compose is asked for the config of the generated file, which is
refused if it differs from what was checked (Project.prepare). The price is that
compose runs as a child process (so the file can be removed afterwards) and
shows the temporary file as its config file.
"""

import contextlib
import itertools
import json
import os
import tempfile
from collections.abc import Callable, Iterator, Sequence
from typing import Any, NamedTuple

from dockscreen.cli import userargs
from dockscreen.compose import inspect, runoptions, serviceusers
from dockscreen.host import shellenv
from dockscreen.host.dockerclient import Docker, DockerError, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import STRICT, TRUSTED, Origin
from dockscreen.model.project import Project
from dockscreen.screen import hardening, policy, substitutions, verdict
from dockscreen.screen.decisions import Decisions
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.scope import Scope
from dockscreen.util import commandline, messages

# Options that select the files and the project; ours replace them.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")


class Screened(NamedTuple):
    """Outcome of screening a compose project stage by stage (Compose.screen): what the last stage that ran
    found, what was decided about the images if it got that far, and the project that will run, which only a
    screening that passed every stage has.
    """
    report: Report
    decided: Decisions | None = None
    final: Project | None = None


class Compose(NamedTuple):
    """Docker compose on one project, as dockscreen drives it: the options that select the project, the
    project as compose resolved it, the substitutions that add the defaults to it (hardening), and the
    scope it is screened in.

    What runs is the resolved project with every substitution made, in order: the hardening, then what
    the images decided (final). Nothing else changes the definition that compose gets.
    """
    global_args: list          # the compose options that select it
    resolved: Project          # as compose resolved it, with remote looked up
    hardening: list            # the substitutions that add the defaults (substitutions.Substitution)
    scope: Scope               # to pull, build, decide and run with

    @property
    def hardened(self) -> Project:
        """Returns the project with the defaults added, which is what the images are acquired for."""
        return substitutions.applied(self.resolved, self.hardening)

    @property
    def directory(self) -> str:
        """Returns the project directory."""
        return self.resolved.directory

    @property
    def remote(self) -> bool:
        """Tells whether the daemon may not be this host's own."""
        return bool(self.resolved.remote)

    def static(self) -> Project:
        """Returns the hardened project as the checks before any image is looked at see it, which leave the
        users that the images decide to later.
        """
        hardened = self.hardened
        unset = hardened.services_without_user
        return hardened.with_origins({name: {"user": Origin.IMAGE} for name in unset})

    def static_policy(self) -> policy.Policy:
        """Returns the policy for the checks before any image is looked at."""
        return self.scope.project_policy(self.resolved)

    def screen(self, command: Callable[[dict[str, Any]], list[str]], parsed: userargs.Parsed | None = None,
               strict: bool = False, announce: Callable[[], None] = lambda: None) -> Screened:
        """Screens the project for a command that starts its containers, stage by stage, each only once the
        one before it passed: the project before any image is looked at (static), the containers that
        already have its name, its images (prepare), and the project that will run (final).

        command: the compose command line on a generated file (generated()).
        parsed: the arguments of the subcommand, with the user the command line chose (compose_run).
        strict: --strict-screen was given, so the service as `run`'s options change it (runoptions) is
        judged, with the command line untrusted; otherwise those options are taken as given, as for
        `docker run`. announce: called before any image is pulled or built.
        """
        static_policy = self.static_policy()
        found = Report.of(static_policy.check_project(self.static()))
        if found.passed:  # asking docker about the name is left until nothing else stands in the way
            static, failures = self._with_name_users(self.static())
            found = Report.of([*static_policy.check_project(static), *failures])
        if not found.passed:
            return Screened(found)
        announce()
        args, chosen = (parsed.args, _chosen(parsed)) if parsed else ([], frozenset())
        hardened = self.hardened
        decided = self.prepare(command(hardened.definition), hardened, args, chosen)
        if not decided.report.passed:
            return Screened(decided.report, decided)
        final = self.final(decided)
        judged, trust = (final, TRUSTED)
        if strict and parsed:
            judged, trust = _as_run(final, parsed, self.scope.runtime), STRICT
        checked = Report.of(self.final_policy(decided).with_trust(trust).check_project(judged))
        return Screened(checked, decided, final if checked.passed else None)

    def _with_name_users(self, project: Project) -> tuple[Project, list[Finding]]:
        """Returns project with the directories its name's containers were made from (inspect.made_from),
        and the failure to look, if any.

        Not looked at for a name the caller chose, or on a daemon that may not be this host's.
        """
        name = project.name
        if not name or project.remote is not False or inspect.names_project(self.global_args,
                                                                           self.scope.runtime.env):
            return project, []
        try:
            return project.with_made_from(inspect.made_from(name, self.scope.docker)), []
        except DockerError as e:
            return project, [inspect.name_lookup_failure(name, e)]

    def final(self, decided: Decisions) -> Project:
        """Returns the project that will run: the resolved one with the hardening and then what the images
        decided (Decisions.changes) made, with where the values dockscreen set come from.
        """
        return substitutions.applied(self.resolved, [*self.hardening, *decided.changes()])

    def final_policy(self, decided: Decisions) -> policy.Policy:
        """Returns the policy for the project that will run, with image sections only where its images, as
        they were found, proved them.
        """
        return decided.policy

    def prepare(self, command: Sequence[str], project: Project, args: Sequence[str] = (),
                chosen: frozenset[str] = frozenset()) -> Decisions:
        """Gets the images of project's services and decides their users (serviceusers.prepare), once compose
        has been shown to read the generated file back as its definition.

        Returns failed Decisions, with nothing pulled or built, if compose reads it differently.
        command: the compose command line on the generated file of project's definition (generated()).
        args and chosen: as serviceusers.prepare takes them.
        """
        problem = _read_back_problem(command, project.definition, self.scope.docker)
        if problem:
            return serviceusers.decided(project, self.scope, (Finding(problem, Severity.FAILED),))
        return serviceusers.prepare(command, project, list(args), self.scope, chosen)

    def surroundings(self) -> list[Finding]:
        """Returns what the policy finds in what the project gets from around it: configured mount dirs that
        contain sensitive paths (Policy.check_mount_dirs), and variables its services take from the shell
        (Policy.check_shell_env).
        """
        runtime, here = self.scope.runtime, self.scope.policy_for(self.directory)
        return [*here.check_mount_dirs(inspect.sensitive_mount_dirs(runtime)),
                *here.check_shell_env(shellenv.copied(self.hardened.definition, runtime.env))]

    def generated(self) -> contextlib.AbstractContextManager[Callable[[dict[str, Any]], list[str]]]:
        """Returns _generated() for this project."""
        return _generated(self.global_args, self.directory, self.scope.docker.binary)


def load_project(global_args: list[str], runtime: Runtime, allow_me: bool) -> Compose:
    """Loads the project global_args select, hardened.

    Raises inspect.Refused if the policy refuses where it is, DockerError if it cannot be inspected,
    ValueError if it cannot be hardened.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    found = inspect.project(global_args, runtime).with_remote(is_remote(global_args, runtime.docker))
    changes = hardening.changes(found.definition, runtime.accounts)
    return Compose(global_args, found, changes, Scope(runtime, allow_me))


def check_and_run(global_args: list[str], sub: str, parsed: userargs.Parsed, runtime: Runtime,
                  allow_me: bool = False, strict: bool = False) -> int:
    """Runs `docker compose global_args sub` with parsed's arguments, sub a subcommand that starts
    containers, on the project global_args select if it passes the checks.

    Returns the exit status: 1 if the project or its images are refused or cannot be checked, else the
    subcommand's. The images of services that set no user are acquired first, by the project's pull policy,
    and decided on (serviceusers); the config that runs is the one that was checked, with the result.
    parsed: the subcommand's arguments, with the user the command line chose (compose_run).
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    strict: --strict-screen was given, so the service as `run`'s options change it (runoptions) is judged,
    with the command line untrusted; otherwise those options are taken as given, as for `docker run`.
    """
    try:
        project = load_project(global_args, runtime, allow_me)
    except DockerError as e:
        verdict.screened(Report.failure(e))
        return 1
    except inspect.Refused as e:
        verdict.screened(Report.of(e.findings))
        return 1
    except ValueError as e:
        verdict.screened(Report.refusal(str(e)))
        return 1

    scope = project.scope
    lines = [*parsed.notices, *project.surroundings(),
             verdict.root_default_notice(scope.settings_in(project.directory).default_user),
             *substitutions.describe(project.hardening)]
    with project.generated() as command:
        screened = project.screen(command, parsed, strict)
        if screened.final is None or screened.decided is None:  # it did not pass every stage
            verdict.screened(screened.report)
            return 1
        for line in [*lines, *screened.decided.notices()]:
            if line:
                messages.notice(line)
        verdict.screened(screened.report)
        return scope.docker.run_child([*command(screened.final.definition), sub, *parsed.args])


def _as_run(final: Project, parsed: userargs.Parsed, runtime: Runtime) -> Project:
    """Returns the final project with the service that `run` runs changed by its options (runoptions)."""
    name = parsed.service
    if name is None or name not in (final.definition.get("services") or {}):
        return final  # compose refuses to run it
    return substitutions.applied(final, runoptions.substitutions(parsed, final.service(name), runtime))


def _chosen(parsed: userargs.Parsed) -> frozenset[str]:
    """Returns the services whose user the command line chooses: `run -u uid:gid` or `run --as NAME`."""
    return frozenset({parsed.service}) if parsed.user_given and parsed.service else frozenset()


@contextlib.contextmanager
def _generated(global_args: Sequence[str], project_dir: str,
               docker_binary: str) -> Iterator[Callable[[dict[str, Any]], list[str]]]:
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
