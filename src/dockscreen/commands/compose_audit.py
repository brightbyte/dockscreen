"""This module implements `docker compose audit`, dockscreen's own command, which reports what `up` would do
without starting anything.

`global_args` are the compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), which
select the project.
"""

from collections.abc import Sequence

from dockscreen.compose import inspect, projectscreening
from dockscreen.host.dockerclient import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.screen import substitutions, verdict
from dockscreen.screen.findings import Report
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, messages

HARDEN_HINT = "the harden subcommand prints a compose override file with these fixes"


def audit(global_args: list[str], args: Sequence[str], runtime: Runtime, allow_me: bool = False) -> int:
    """Runs the checks that screen `up` without starting anything; pulls and builds images as up would.

    Exit status 0 if `up` would run, 1 if it would refuse, 3 if the audit failed to get that far
    (verdict). --brief prints only the verdict, in one line.
    """
    brief = args == [commandline.BRIEF]
    if args and not brief:
        messages.notice(f"usage: dockscreen compose [compose options] audit [{commandline.BRIEF}]")
        return 2
    try:
        loaded = projectscreening.load_project(global_args, runtime)
    except DockerError as e:
        return verdict.report(Report.failure(e), brief)
    except inspect.Refused as e:
        return verdict.report(Report.of(e.findings), brief)
    except ValueError as e:
        return verdict.report(Report.refusal(str(e)), brief)

    screener = Screener(runtime, allow_me)
    outcome, lines = _audit_images(loaded, screener, brief)
    if not brief:
        around = projectscreening.surroundings(loaded, screener)
        for line in [*substitutions.describe(loaded.hardening), *around, *lines]:
            messages.out(line)
        if outcome.reasons or loaded.hardening:
            messages.out(messages.Marked(messages.HINT, HARDEN_HINT))
    return verdict.report(outcome, brief)


def _audit_images(loaded: projectscreening.Loaded, screener: Screener, brief: bool
                  ) -> tuple[Report, Sequence[str]]:
    """Screens the project as `up` would, stage by stage (projectscreening), pulling and building its images
    if the checks before them pass.

    Returns (what the last stage found, report lines).
    """
    cleared = projectscreening.check(loaded, screener)
    if isinstance(cleared, Report):
        return cleared, [
            "the images were not looked at because of the problems below: nothing was pulled or built"]
    if not brief:
        messages.notice("pulling or building the images as `up` would, to look at the users they run as")
    with loaded.generated(screener.docker.binary) as command:
        decided = projectscreening.decide(cleared, screener, command)
    # the last stage is what `up` checks once more before it runs: image sections need proof then
    runnable = projectscreening.finish(cleared, decided, screener)
    return (runnable if isinstance(runnable, Report) else runnable.report), decided.describe()
