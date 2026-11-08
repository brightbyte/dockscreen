"""This module provides functions for reporting the verdict of screening a command or of an audit (see
findings for what the verdicts mean)."""

from dockscreen.screen.findings import Finding, Report, Verdict
from dockscreen.util import messages
from dockscreen.util.messages import printable

ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}

# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


def line(verdict: Verdict) -> messages.Message:
    """Builds the closing line of an audit, or of the check before a command runs: mark and verdict."""
    return messages.Message(ICONS[verdict], LINES[verdict])


def brief(found: Report) -> messages.Message:
    """Builds the verdict of what was found as one line, for --brief: the closing line, then the first
    reason if it did not pass and how many more there are.
    """
    verdict, reasons = found.verdict, found.reasons
    if verdict is Verdict.PASSED:
        return line(verdict)
    first = printable(messages.with_output(reasons[0]))
    more = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""
    return messages.Message(ICONS[verdict], f"{LINES[verdict]}: {first}{more}")


def report(found: Report, brief_mode: bool = False) -> int:
    """Prints the verdict of what was found and returns the verdict's int value as the exit status.

    Parameters:
    - found: the report
    - brief_mode: print one line on stdout (brief); otherwise each finding that does not stop the command,
      each reason and the closing line go to stderr
    """
    verdict = found.verdict
    if brief_mode:
        messages.out(brief(found), indent=False)
        return int(verdict)
    for finding in found.findings:
        if not finding.fatal:
            messages.notice(finding)
    for reason in found.reasons:
        flat = Finding.of(reason)  # the subject becomes part of the text
        messages.notice(flat.replace(text=f"refusing: {flat}") if verdict is Verdict.REFUSED else flat)
    messages.notice(line(verdict))
    return int(verdict)


def screened(found: Report) -> bool:
    """Prints the verdict of screening a command and returns whether it may run."""
    report(found)
    return found.passed
