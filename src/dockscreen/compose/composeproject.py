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
from dockscreen.host.dockerclient import Docker, DockerNotFound, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import STRICT, TRUSTED, Origin
from dockscreen.model.project import Project
from dockscreen.screen import findings, hardening, imagedecision, policy, substitutions, verdict
from dockscreen.screen.findings import Finding, Report
from dockscreen.screen.scope import Scope
from dockscreen.util import commandline, messages

# Options that select the files and the project; ours replace them.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")


class Compose(NamedTuple):
    """Docker compose on one project, as dockscreen drives it: the options that select the project, the
    project with the defaults added (hardened), the substitutions that added them, and the scope it is
    screened in.
    """
    global_args: list          # the compose options that select it
    project: Project           # hardened, with remote looked up
    hardening: list            # the substitutions that hardened it (substitutions.Substitution)
    scope: Scope               # with the project's directory; to pull, build, decide and run with

    @property
    def hardened(self) -> dict[str, Any]:
        """Returns the project's definition with the defaults added."""
        return self.project.definition

    @property
    def directory(self) -> str:
        """Returns the project directory."""
        return self.project.directory

    @property
    def remote(self) -> bool:
        """Tells whether the daemon may not be this host's own."""
        return bool(self.project.remote)

    def static(self) -> Project:
        """Returns the project as the checks before any image is looked at see it, which leave the users
        that the images decide to later.
        """
        unset = serviceusers.unset_user_services(self.hardened)
        return self.project.with_origins({name: {"user": Origin.IMAGE} for name in unset})

    def static_policy(self) -> policy.Policy:
        """Returns the policy context for the checks before any image is looked at."""
        return self.scope.project_policy()

    def problems(self) -> list[Finding]:
        """Returns what is refused before any image is looked at; empty if nothing is."""
        static = self.static_policy()
        problems = static.check_project(self.static()) + static.check_daemon(self.remote)
        # the name check asks the daemon, which must be this host's
        if not problems and not inspect.names_project(self.global_args, self.scope.runtime.env):
            problems += inspect.name_conflicts(static, self.hardened["name"], self.directory,
                                              self.scope.docker)
        return problems

    def final(self, prepared: serviceusers.Prepared) -> Project:
        """Returns the project that will run (Prepared.changes applied), with where the values dockscreen set
        come from.
        """
        return substitutions.applied(self.project, prepared.changes())

    def final_policy(self, prepared: serviceusers.Prepared) -> policy.Policy:
        """Returns the policy context for the project that will run, with image sections only where prepared
        proved them.
        """
        return self.scope.project_policy(prepared.verified)

    def prepare(self, command: Sequence[str], config: dict[str, Any], args: Sequence[str] = (),
                chosen: frozenset[str] = frozenset()) -> serviceusers.Prepared:
        """Gets the images of config's services and decides their users (serviceusers.prepare), once compose
        has been shown to read the generated file back as config.

        Returns a failed Prepared, with nothing pulled or built, if compose reads it differently.
        command: the compose command line on config's generated file (generated()).
        args and chosen: as serviceusers.prepare takes them.
        """
        problem = _read_back_problem(command, config, self.scope.docker)
        if problem:
            return serviceusers.Prepared(config, self.scope, {}, Report.failure(problem))
        return serviceusers.prepare(command, config, list(args), self.scope, chosen)

    def generated(self) -> contextlib.AbstractContextManager[Callable[[dict[str, Any]], list[str]]]:
        """Returns _generated() for this project."""
        return _generated(self.global_args, self.directory, self.scope.docker.binary)


def load_project(global_args: list[str], runtime: Runtime, allow_me: bool) -> Compose:
    """Loads the project global_args select, hardened.

    Raises inspect.Refused if the policy refuses where it is, inspect.InspectError if it cannot be inspected,
    ValueError if it cannot be hardened.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    found = inspect.project(global_args, runtime).with_remote(is_remote(global_args, runtime.docker))
    _, changes = hardening.apply(found.definition, runtime.accounts)
    scope = Scope(runtime, allow_me, found.directory)
    return Compose(global_args, substitutions.applied(found, changes), changes, scope)


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
        problems = project.problems()
    except (inspect.InspectError, DockerNotFound) as e:
        verdict.screened(Report.failure(e))
        return 1
    except inspect.Refused as e:
        problems = e.findings
    except ValueError as e:
        problems = findings.refused([str(e)])
    if problems:
        verdict.screened(Report.of(problems))
        return 1

    hardened, scope = project.hardened, project.scope
    lines = [*parsed.notices, *inspect.mount_dir_warnings(runtime),
             imagedecision.root_default_notice(scope), *substitutions.describe(project.hardening)]
    lines += shellenv.describe(hardened, runtime.env)
    with project.generated() as command:
        prepared = project.prepare(command(hardened), hardened, parsed.args, _chosen(parsed))
        if not prepared.report.passed:
            verdict.screened(prepared.report)
            return 1
        final = project.final(prepared)
        judged, trust = (_as_run(final, parsed, runtime), STRICT) if strict else (final, TRUSTED)
        checked = Report.of(project.final_policy(prepared).with_trust(trust).check_project(judged))
        if not checked.passed:  # what will run
            verdict.screened(checked)
            return 1
        for line in [*lines, *prepared.notices()]:
            if line:
                messages.notice(line)
        verdict.screened(checked)
        return scope.docker.run_child([*command(final.definition), sub, *parsed.args])


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
