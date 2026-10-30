"""The outcome of an audit, which is also its exit status, and of the screening before a command runs.

Refused means the policy says no. Failed means the audit could not get far enough to judge: docker,
the image or the compose config was not there, or pulling or building failed. A refusal is about the
project, image or command line; a failure is about getting to them, and may go away when retried.
Exit status 2 is left for usage errors.
"""

import enum

from dockscreen import messages
from dockscreen.imagedecision import Kind
from dockscreen.messages import printable


class Verdict(enum.IntEnum):
    PASSED = 0
    REFUSED = 1
    FAILED = 3


ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}


def dot(assessment):
    """Returns the mark for an assessment of an image's user: BAD if refused, GOOD if accepted, else WARN."""
    if assessment.refused:
        return messages.BAD
    return messages.GOOD if assessment.kind in (Kind.OK, Kind.CONFIGURED) else messages.WARN


# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


def line(verdict):
    """Builds the closing line of an audit, or of the check before a command runs: mark and verdict."""
    return messages.Marked(ICONS[verdict], LINES[verdict])


def brief(verdict, reasons):
    """Builds the verdict as one line, for --brief: the closing line, then the first reason if it did not
    pass and how many more there are.
    """
    if verdict is Verdict.PASSED:
        return line(verdict)
    first = printable(reasons[0]) if reasons else "no reason given"
    more = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""
    return messages.Marked(ICONS[verdict], f"{LINES[verdict]}: {first}{more}")


def report(verdict, reasons, brief_mode=False):
    """Prints the verdict and returns it as the exit status.

    brief_mode: print one line on stdout (brief); otherwise each reason and the closing line go to stderr.
    """
    if brief_mode:
        messages.out(brief(verdict, reasons), indent=False)
        return int(verdict)
    for reason in reasons:
        text = f"refusing: {reason}" if verdict is Verdict.REFUSED else reason
        messages.notice(messages.Marked(messages.BAD, text, messages.help_of(reason)))
    messages.notice(line(verdict))
    return int(verdict)


def screened(reasons, failed=False):
    """Prints the verdict of screening a command and returns whether it may run: only if there are no
    reasons.

    reasons: why it may not; failed: the reasons are failures to look, not refusals.
    """
    outcome = Verdict.FAILED if failed else Verdict.REFUSED if reasons else Verdict.PASSED
    report(outcome, reasons)
    return outcome is Verdict.PASSED
