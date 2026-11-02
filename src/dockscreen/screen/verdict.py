"""This module defines how the verdict of screening a command or of an audit is reported (see findings for
what the verdicts mean).
"""

from dockscreen.screen.findings import Report, Severity, Verdict
from dockscreen.screen.imagedecision import Assessment, Kind
from dockscreen.util import messages
from dockscreen.util.messages import printable

ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}


def dot(assessment: Assessment) -> messages.Mark:
    """Returns the mark for an assessment of an image's user: BAD if refused, GOOD if accepted, else WARN."""
    if assessment.refused:
        return messages.BAD
    return messages.GOOD if assessment.kind in (Kind.OK, Kind.CONFIGURED) else messages.WARN


# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


def line(verdict: Verdict) -> messages.Marked:
    """Builds the closing line of an audit, or of the check before a command runs: mark and verdict."""
    return messages.Marked(ICONS[verdict], LINES[verdict])


def brief(found: Report) -> messages.Marked:
    """Builds the verdict of what was found as one line, for --brief: the closing line, then the first
    reason if it did not pass and how many more there are.
    """
    verdict, reasons = found.verdict, found.reasons
    if verdict is Verdict.PASSED:
        return line(verdict)
    first = printable(messages.with_output(reasons[0]))
    more = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""
    return messages.Marked(ICONS[verdict], f"{LINES[verdict]}: {first}{more}")


def report(found: Report, brief_mode: bool = False) -> int:
    """Prints the verdict of what was found and returns it as the exit status.

    brief_mode: print one line on stdout (brief); otherwise each finding that does not stop the command,
    each reason and the closing line go to stderr.
    """
    verdict = found.verdict
    if brief_mode:
        messages.out(brief(found), indent=False)
        return int(verdict)
    for finding in found.findings:
        if not finding.fatal:
            mark = messages.WARN if finding.severity is Severity.NOTABLE else messages.ROUTINE
            messages.notice(messages.Marked(mark, finding, finding.help, finding.output))
    for reason in found.reasons:
        text = f"refusing: {reason}" if verdict is Verdict.REFUSED else reason
        messages.notice(messages.Marked(messages.BAD, text, reason.help, reason.output))
    messages.notice(line(verdict))
    return int(verdict)


def screened(found: Report) -> bool:
    """Prints the verdict of screening a command and returns whether it may run."""
    report(found)
    return found.passed
