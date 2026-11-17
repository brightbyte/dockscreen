"""This module defines the Report of what one screening reported, and how it is shown: a report is what a
command or an audit ends by showing, and its verdict (finding.Verdict), the worst of its findings, is the
exit status of an audit.

Use it to build a report from findings (Report.of, Report.refusal, Report.failure, Report.with_more_findings)
and to show it (Report.show, Report.show_screening).
"""

from collections.abc import Iterable
from typing import NamedTuple, Self

from dockscreen.policy.finding import Finding, ReportEntry, Verdict, failure_of
from dockscreen.policy.notice import Notice
from dockscreen.util import messages
from dockscreen.util.messages import printable_text

ICONS = {Verdict.PASSED: messages.PASSED_MARK, Verdict.REFUSED: messages.REFUSED_MARK,
         Verdict.FAILED: messages.FAILED_MARK}

# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


class Report(NamedTuple):
    """Record of what one screening reported, from which its verdict follows. It holds the notices and the
    findings, each in their order.

    Build one with of, or with refusal or failure for a single reason; show it with show, or with
    show_screening before a command runs.

    Attributes:
    - notices: what was reported without stopping the command (Notice)
    - findings: what stops the command (Finding)
    """
    notices: tuple[Notice, ...] = ()
    findings: tuple[Finding, ...] = ()

    @classmethod
    def of(cls, entries: Iterable[ReportEntry]) -> Self:
        """Returns the report of entries, with the notices and the findings each in their order."""
        entries = list(entries)
        return cls(tuple(r for r in entries if isinstance(r, Notice)),
                   tuple(r for r in entries if isinstance(r, Finding)))

    @classmethod
    def refusal(cls, reason: object) -> Self:
        """Returns the report of a single refusal (Finding.of)."""
        return cls((), (Finding.of(reason, Verdict.REFUSED),))

    @classmethod
    def failure(cls, reason: object) -> Self:
        """Returns the report of a single failure to look.

        Parameters:
        - reason: an error (failure_of), or a text
        """
        if isinstance(reason, BaseException):
            return cls((), (failure_of(reason),))
        return cls((), (Finding.of(reason, Verdict.FAILED),))

    def with_more_findings(self, extra_entries: Iterable[ReportEntry]) -> Self:
        """Returns a report of what this one holds, then more."""
        return type(self).of([*self.notices, *self.findings, *extra_entries])

    @property
    def verdict(self) -> Verdict:
        """Returns the worst verdict of the findings: FAILED if anything could not be looked at, else REFUSED
        if anything is refused, else PASSED.
        """
        return max((f.verdict for f in self.findings), default=Verdict.PASSED)

    @property
    def has_passed(self) -> bool:
        """Tells whether the command may run."""
        return not self.findings

    @property
    def closing_line(self) -> messages.Message:
        """Returns the closing line of an audit, or of the check before a command runs: mark and verdict."""
        return messages.Message(ICONS[self.verdict], LINES[self.verdict])

    @property
    def brief_line(self) -> messages.Message:
        """Returns the verdict as one line, for --brief: the closing line, then the first reason if it did
        not pass and how many more there are.
        """
        if self.has_passed:
            return self.closing_line
        first_finding = printable_text(messages.with_output(self.findings[0]))
        count_suffix = f" (+{len(self.findings) - 1} more)" if len(self.findings) > 1 else ""
        return messages.Message(ICONS[self.verdict], f"{LINES[self.verdict]}: {first_finding}{count_suffix}")

    def show(self, should_be_brief: bool = False) -> int:
        """Prints the verdict and returns its int value as the exit status.

        Parameters:
        - should_be_brief: print one line on stdout (brief); otherwise each notice, each finding and the
          closing line go to stderr
        """
        if should_be_brief:
            messages.print_line(self.brief_line, should_indent=False)
            return int(self.verdict)
        for notice in self.notices:
            messages.print_notice(notice)
        for finding in self.findings:
            flat_finding = Finding.of(finding)  # the subject becomes part of the text
            is_refusal = self.verdict is Verdict.REFUSED
            if is_refusal:
                flat_finding = flat_finding.with_text(f"refusing: {flat_finding}")
            messages.print_notice(flat_finding)
        messages.print_notice(self.closing_line)
        return int(self.verdict)

    def show_screening(self) -> bool:
        """Prints the verdict of screening a command and returns whether it may run."""
        self.show()
        return self.has_passed
