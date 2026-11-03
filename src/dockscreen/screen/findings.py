"""This module defines classes for recording what screening finds out about what it screens, and the verdict
that follows from it.

A finding says one thing about one subject (a service, an image, a container, the command line) and how
much it matters: routine and notable findings are reported, refused and failed ones stop the command.
Everything screening reports is one, also what dockscreen changes in what it runs: routine if it rarely
matters, notable if it can change how something runs.
Refused means the policy says no. Failed means screening could not get far enough to judge: docker, the
image or the compose config was not there, or pulling or building failed. A refusal is about the project,
image or command line; a failure is about getting to them, and may go away when retried.

The verdict is also the exit status of an audit. Exit status 2 is left for usage errors.
"""

import enum
from collections.abc import Iterable
from typing import NamedTuple, Self

from dockscreen.model.origin import Origin
from dockscreen.util import messages


class Severity(enum.Enum):
    """Enum of how much a finding matters to whoever runs the command."""
    ROUTINE = "routine"  # reported; rarely changes how anything runs
    NOTABLE = "notable"  # reported; worth a look, it can change how something runs
    REFUSED = "refused"  # the policy says no
    FAILED = "failed"    # screening could not look

    @property
    def fatal(self) -> bool:
        """Tells whether a finding of this severity stops the command."""
        return self in (Severity.REFUSED, Severity.FAILED)


# The mark a finding is shown with, by its severity.
MARKS = {Severity.ROUTINE: messages.ROUTINE, Severity.NOTABLE: messages.WARN, Severity.REFUSED: messages.BAD,
         Severity.FAILED: messages.BAD}


class Finding(messages.Marked):
    """Value object for a statement about one subject of screening and how much it matters, which prints as a
    line marked by its severity (MARKS). Its string value is its text, after the subject and a colon if there
    is one, without the mark. It holds the subject and the severity besides what a Marked line holds.

    - subject: what it is about ("service web"), or None
    - severity: how much it matters
    - text, help, output: as in Marked

    The str base does not protect these attributes, so nothing changes them after construction. Build one with
    the constructor, or with of from a text or another finding.
    """

    severity: Severity
    subject: str | None

    def __new__(cls, text: str, severity: Severity = Severity.REFUSED, subject: str | None = None,
                help: str | None = None, output: str | None = None) -> Self:
        finding = str.__new__(cls, f"{subject}: {text}" if subject else text)
        finding.mark, finding.text = MARKS[severity], text
        finding.severity, finding.subject = severity, subject
        finding.help, finding.output = help, output or None
        return finding

    @property
    def shown(self) -> str:
        """Returns the subject and text, followed by the help if there is one and helpful mode is on."""
        return messages.with_help(str(self), self.help)

    @classmethod
    def of(cls, reason: object, severity: Severity | None = None, subject: str | None = None) -> Self:
        """Returns reason as a finding of severity about subject, keeping its help and output.

        reason: a text, or a Finding, whose own subject becomes part of the text.
        severity: if None, a Finding's own, else REFUSED.
        """
        if severity is None:
            severity = reason.severity if isinstance(reason, Finding) else Severity.REFUSED
        return cls(str(reason), severity, subject, messages.help_of(reason), messages.output_of(reason))

    @property
    def fatal(self) -> bool:
        """Tells whether this finding stops the command."""
        return self.severity.fatal


def failure_of(error: BaseException, subject: str | None = None, help: str | None = None) -> Finding:
    """Returns the failure to look that error reports, about subject if given, with what to do about it
    (help) if given, and what docker printed about it if the error carries that (an `output`).
    """
    return Finding(str(error), Severity.FAILED, subject, help, getattr(error, "output", None))


def about(found: Iterable[Finding], subject: str) -> list[Finding]:
    """Returns each finding of found as one about subject, which its own subject becomes part of the text of,
    with its severity.
    """
    return [Finding.of(f, subject=subject) for f in found]


def refused(reasons: Iterable[object], subject: str | None = None) -> list[Finding]:
    """Returns each of reasons as a refusal (Finding.of), about subject if given."""
    return [Finding.of(r, Severity.REFUSED, subject) for r in reasons]


def failed(reasons: Iterable[object], subject: str | None = None) -> list[Finding]:
    """Returns each of reasons as a failure to look (Finding.of), about subject if given."""
    return [Finding.of(r, Severity.FAILED, subject) for r in reasons]


def judged(reasons: Iterable[object], origin: Origin, trust: Iterable[Origin], subject: str | None = None
           ) -> list[Finding]:
    """Returns each of reasons, what the policy refuses in a value from origin, as a refusal; or as a
    notable finding if origin is in trust, whose values are taken as given.
    """
    severity = Severity.NOTABLE if origin in trust else Severity.REFUSED
    return [Finding.of(r, severity, subject) for r in reasons]


class Verdict(enum.IntEnum):
    """Enum of the outcomes of an audit, or of the screening before a command runs. Its value is the exit
    status.
    """
    PASSED = 0
    REFUSED = 1
    FAILED = 3


class Report(NamedTuple):
    """Record of what one screening found, from which its verdict follows. It holds the findings, in their
    order.

    - findings: what was found

    Build one with of, or with refusal or failure for a single reason.
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
        """Returns the report of a single failure to look: an error (failure_of), or a text."""
        if isinstance(reason, BaseException):
            return cls((failure_of(reason),))
        return cls((Finding.of(reason, Severity.FAILED),))

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
