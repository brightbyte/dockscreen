"""This module defines the Report of what one screening found, the verdict that follows from it, and how both
are shown: a report is what a command or an audit ends by showing, and its verdict is the exit status of an
audit. Exit status 2 is left for usage errors.

Use it to build a report from findings (Report.of, Report.refusal, Report.failure, Report.with_more_findings)
and to show it (Report.show, Report.show_screening).
"""

import enum
from collections.abc import Iterable
from typing import NamedTuple, Self

from dockscreen.screen.findings import Finding, Severity, failure_of
from dockscreen.util import messages
from dockscreen.util.messages import printable


class Verdict(enum.IntEnum):
    """Enum of the outcomes of an audit, or of the screening before a command runs. Its value is the exit
    status.
    """
    PASSED = 0
    REFUSED = 1
    FAILED = 3


ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}

# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


class Report(NamedTuple):
    """Record of what one screening found, from which its verdict follows. It holds the findings, in their
    order.

    Build one with of, or with refusal or failure for a single reason; show it with show, or with
    show_screening before a command runs.

    Attributes:
    - findings: what was found
    """
    findings: tuple[Finding, ...] = ()

    @classmethod
    def of(cls, findings: Iterable[Finding]) -> Self:
        """Returns the report of findings, in their order."""
        return cls(tuple(findings))

    @classmethod
    def refusal(cls, reason: object) -> Self:
        """Returns the report of a single refusal (Finding.of)."""
        return cls((Finding.of(reason, Severity.REFUSED),))

    @classmethod
    def failure(cls, reason: object) -> Self:
        """Returns the report of a single failure to look.

        Parameters:
        - reason: an error (failure_of), or a text
        """
        if isinstance(reason, BaseException):
            return cls((failure_of(reason),))
        return cls((Finding.of(reason, Severity.FAILED),))

    def with_more_findings(self, more: Iterable[Finding]) -> Self:
        """Returns a report of the findings of this one, then more."""
        return type(self)((*self.findings, *more))

    @property
    def verdict(self) -> Verdict:
        """Returns FAILED if anything could not be looked at, else REFUSED if anything is refused, else
        PASSED.
        """
        severities = {f.severity for f in self.findings}
        if Severity.FAILED in severities:
            return Verdict.FAILED
        return Verdict.REFUSED if Severity.REFUSED in severities else Verdict.PASSED

    @property
    def reasons(self) -> list[Finding]:
        """Returns the findings that stop the command, in their order."""
        return [f for f in self.findings if f.fatal]

    @property
    def passed(self) -> bool:
        """Tells whether the command may run."""
        return self.verdict is Verdict.PASSED

    @property
    def closing_line(self) -> messages.Message:
        """Returns the closing line of an audit, or of the check before a command runs: mark and verdict."""
        return messages.Message(ICONS[self.verdict], LINES[self.verdict])

    @property
    def brief(self) -> messages.Message:
        """Returns the verdict as one line, for --brief: the closing line, then the first reason if it did
        not pass and how many more there are.
        """
        if self.passed:
            return self.closing_line
        first = printable(messages.with_output(self.reasons[0]))
        more = f" (+{len(self.reasons) - 1} more)" if len(self.reasons) > 1 else ""
        return messages.Message(ICONS[self.verdict], f"{LINES[self.verdict]}: {first}{more}")

    def show(self, brief_mode: bool = False) -> int:
        """Prints the verdict and returns its int value as the exit status.

        Parameters:
        - brief_mode: print one line on stdout (brief); otherwise each finding that does not stop the command,
          each reason and the closing line go to stderr
        """
        if brief_mode:
            messages.out(self.brief, indent=False)
            return int(self.verdict)
        for finding in self.findings:
            if not finding.fatal:
                messages.notice(finding)
        for reason in self.reasons:
            flat = Finding.of(reason)  # the subject becomes part of the text
            messages.notice(flat.with_text(f"refusing: {flat}") if self.verdict is Verdict.REFUSED else flat)
        messages.notice(self.closing_line)
        return int(self.verdict)

    def show_screening(self) -> bool:
        """Prints the verdict of screening a command and returns whether it may run."""
        self.show()
        return self.passed
