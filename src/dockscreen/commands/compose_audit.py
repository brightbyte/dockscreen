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
        project = projectscreening.load_project(global_args, runtime, allow_me)
    except DockerError as e:
        return verdict.report(Report.failure(e), brief)
    except inspect.Refused as e:
        return verdict.report(Report.of(e.findings), brief)
    except ValueError as e:
        return verdict.report(Report.refusal(str(e)), brief)

    outcome, lines = _audit_images(project, brief)
    if not brief:
        for line in [*substitutions.describe(project.hardening), *project.surroundings(), *lines]:
            messages.out(line)
        if outcome.reasons or project.hardening:
            messages.out(messages.Marked(messages.HINT, HARDEN_HINT))
    return verdict.report(outcome, brief)


def _audit_images(project: projectscreening.ProjectScreening, brief: bool) -> tuple[Report, Sequence[str]]:
    """Screens the project as `up` would, stage by stage (ProjectScreening.screen), pulling and building its
    images if the checks before them pass.

    Returns (what the last stage found, report lines).
    """
    def announce() -> None:
        if not brief:
            messages.notice("pulling or building the images as `up` would, to look at the users they run as")

    # the last stage is what `up` checks once more before it runs: image sections need proof then
    with project.generated() as command:
        screened = project.screen(command, announce=announce)
    if screened.decided is None:
        return screened.report, [
            "the images were not looked at because of the problems below: nothing was pulled or built"]
    return screened.report, screened.decided.describe()
