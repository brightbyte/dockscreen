"""This module implements `docker compose audit`, dockscreen's own command, which reports what `up` would do
without starting anything.

`global_args` are the compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), which
select the project.
"""

from collections.abc import Sequence

from dockscreen.compose import composeproject, inspect
from dockscreen.host import shellenv
from dockscreen.host.dockerclient import DockerNotFound
from dockscreen.host.runtime import Runtime
from dockscreen.screen import policy, substitutions, verdict
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
        project = composeproject.load_project(global_args, runtime, allow_me)
    except (inspect.InspectError, DockerNotFound) as e:
        return verdict.report(Report.failure(e), brief)
    except (inspect.ScreenError, ValueError) as e:
        return verdict.report(Report.refusal(str(e)), brief)

    outcome, lines = _audit_images(project, brief)
    if not brief:
        warnings = [*inspect.mount_dir_warnings(runtime), *shellenv.describe(project.hardened, runtime.env)]
        for line in [*substitutions.describe(project.hardening), *warnings, *lines]:
            messages.out(line)
        if outcome.reasons or project.hardening:
            messages.out(messages.Marked(messages.HINT, HARDEN_HINT))
    return verdict.report(outcome, brief)


def _audit_images(project: composeproject.Project, brief: bool) -> tuple[Report, Sequence[str]]:
    """Checks the project, then its images if the checks pass.

    Returns (what was found, report lines).
    """
    problems = project.problems()
    if problems:
        return Report.of(problems), [
            "the images were not looked at because of the problems below: nothing was pulled or built"]
    if not brief:
        messages.notice("pulling or building the images as `up` would, to look at the users they run as")
    hardened = project.hardened
    with project.generated() as command:
        prepared = project.prepare(command(hardened), hardened)
    if not prepared.report.passed:
        return prepared.report, prepared.describe()
    # what `up` checks once more before it runs: image sections need proof now
    final, user_origins = prepared.finalize()
    checked = policy.check_config(final, project.final_ctx(prepared, user_origins))
    return Report.of(checked), prepared.describe()
