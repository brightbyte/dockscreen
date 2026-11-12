"""This module provides what compose up, create and run share: having the project screened, printing what
was found, and running compose as a child on the config that was checked, for as long as the generated file
it reads exists (projectscreening).
"""

from collections.abc import Sequence

from dockscreen.host.docker import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.policy import userdecisionview
from dockscreen.policy.notice import Notice
from dockscreen.policy.report import Report
from dockscreen.screen import inspect, projectscreening, userargs
from dockscreen.screen.screener import Screener
from dockscreen.util import messages


def check_and_run(global_args: list[str], sub: str, parsed: userargs.UserArgs[str], runtime: Runtime,
                  allow_me: bool = False, strict: bool = False, notices: Sequence[Notice] = ()) -> int:
    """Runs `docker compose global_args sub` with parsed's arguments, sub a subcommand that starts
    containers, on the project global_args select if it passes the checks.

    Returns the exit status: 1 if the project or its images are refused or cannot be checked, else the
    subcommand's. The images of services that set no user are acquired first, by the project's pull policy,
    and decided on (serviceinfo, imageusers); the config that runs is the one that was checked, with the
    result.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - sub: the subcommand
    - parsed: the subcommand's arguments, with the user the command line chose, resolved
      (userscreening.screened)
    - runtime: the Runtime of the command
    - allow_me: --allow-me was given, so the caller's own ids are allowed
    - strict: --strict-screen was given, so the service as `run`'s options change it (runoptions) is judged,
      with the command line untrusted; otherwise those options are taken as given, as for `docker run`
    - notices: what resolving the user the command line chose did (userscreening.screened), printed with the
      project's notices
    """
    try:
        loaded = projectscreening.load_project(global_args, runtime)
    except DockerError as e:
        Report.failure(e).show_screening()
        return 1
    except inspect.ProjectRefused as e:
        Report.of(e.findings).show_screening()
        return 1
    except ValueError as e:
        Report.refusal(str(e)).show_screening()
        return 1

    screener = Screener(runtime, allow_me)
    lines = [*notices, *projectscreening.surroundings(loaded, screener),
             userdecisionview.root_default_notice(screener.policy(loaded.directory).default_user),
             *loaded.hardening.notices()]
    cleared = projectscreening.check(loaded, screener)
    if isinstance(cleared, Report):
        cleared.show_screening()
        return 1
    with loaded.generated(screener.docker.binary) as command:
        decided = projectscreening.decide(cleared, screener, command, parsed.args, _chosen(parsed))
        runnable = projectscreening.finish(cleared, decided, screener, parsed, strict)
        if isinstance(runnable, Report):
            runnable.show_screening()
            return 1
        for line in [*lines, *decided.notices()]:
            if line:
                messages.notice(line)
        runnable.report.show_screening()
        return screener.docker.run_child([*command(runnable.project.definition), sub, *parsed.args])


def _chosen(parsed: userargs.UserArgs[str]) -> frozenset[str]:
    """Returns the services whose user the command line chooses: `run -u uid:gid` or `run --as NAME`."""
    return frozenset({parsed.service}) if parsed.users.chosen and parsed.service else frozenset()
