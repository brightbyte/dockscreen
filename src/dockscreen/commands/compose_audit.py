"""This module implements `docker compose audit`, dockscreen's own command. It reports the outcome of `up`
without starting anything.

The compose options before the subcommand (e.g. ["-f", "x.yml"]), which select the project, are the lead_args
of the command line.
"""

from collections.abc import Sequence

from dockscreen.commands import helptext
from dockscreen.host.docker import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.screen import inspect, projectscreening
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, messages

HARDEN_HINT = "the harden subcommand prints a compose override file with these fixes"


def audit(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs the checks that screen `up`, without starting anything. Pulls and builds images as `up` would.

    Exit status 0 if `up` would run, 1 if it would refuse, 3 if the audit failed to get that far
    (Report.verdict). --brief prints only the verdict, in one line.

    Parameters:
    - parent_cli: the compose command line, with `audit` as its command; its arguments are none, or --brief
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "audit"
    args, global_args = list(parent_cli.args), list(parent_cli.lead_args)
    is_brief = args == [commandline.BRIEF_OPTION]
    if args and not is_brief:
        usage = f"usage: dockscreen compose [compose options] audit [{commandline.BRIEF_OPTION}]"
        messages.print_notice(usage)
        return 2
    try:
        loaded_project = projectscreening.load_project(global_args, runtime)
    except DockerError as e:
        return Report.failure(e).show(is_brief)
    except inspect.ProjectRefusal as e:
        return Report.of(e.findings).show(is_brief)
    except ValueError as e:
        return Report.refusal(str(e)).show(is_brief)

    screener = Screener(runtime, parent_cli.is_me_allowed)
    outcome, lines = _audit_images(loaded_project, screener, is_brief)
    if not is_brief:
        around = projectscreening.surroundings(loaded_project, screener)
        report_lines: list[str | messages.HasMark] = [*loaded_project.hardening.notices(), *around, *lines]
        for line in report_lines:
            messages.print_line(line)
        if outcome.findings or loaded_project.hardening:
            messages.print_line(messages.Message(messages.HINT, HARDEN_HINT))
    return outcome.show(is_brief)


def _audit_images(loaded_project: projectscreening.LoadedProject, screener: Screener, should_be_brief: bool
                  ) -> tuple[Report, Sequence[str | messages.HasMark]]:
    """Screens the project as `up` would, stage by stage (projectscreening), pulling and building its images
    if the checks before them pass.

    Returns the report of the last stage, and the lines to print.
    """
    check_result = projectscreening.check(loaded_project, screener)
    if isinstance(check_result, Report):
        return check_result, [
            "the images were not looked at because of the problems below: nothing was pulled or built"]
    if not should_be_brief:
        messages.print_notice("pulling or building the images as `up` would, to look at the users they run "
                              "as")
    cleared_project = check_result
    with loaded_project.generated_files(screener.docker.binary) as command:
        decisions = projectscreening.decide(cleared_project, screener, command)
    # the last stage is the check that `up` repeats before it runs; image sections need proof at that point
    finish_result = projectscreening.finish(cleared_project, decisions, screener)
    final_report = finish_result if isinstance(finish_result, Report) else finish_result.report
    return final_report, decisions.describe()


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name, from the docstring of audit.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    return helptext.command_topic(name, audit, options=(helptext.BRIEF_HELP,))
