"""This module defines what screening finds out about what it screens, and the verdict that follows.

A finding says one thing about one subject (a service, an image, a container, the command line) and how
much it matters: routine and notable findings are reported, refused and failed ones stop the command.
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
    """Degree to which a finding matters to whoever runs the command."""
    ROUTINE = "routine"  # reported; rarely changes how anything runs
    NOTABLE = "notable"  # reported; worth a look, it can change how something runs
    REFUSED = "refused"  # the policy says no
    FAILED = "failed"    # screening could not look

    @property
    def fatal(self) -> bool:
        """Tells whether a finding of this severity stops the command."""
        return self in (Severity.REFUSED, Severity.FAILED)


class Finding(messages.Reason):
    """Statement about one subject of screening, with how much it matters and, as a Reason, what to do
    about it and what docker printed.

    Its string value is the text, after the subject and a colon if there is a subject.
    """

    text: str
    severity: Severity
    subject: str | None

    def __new__(cls, text: str, severity: Severity = Severity.REFUSED, subject: str | None = None,
                help: str | None = None, output: str | None = None) -> Self:
        finding = super().__new__(cls, f"{subject}: {text}" if subject else text, help, output)
        finding.text, finding.severity, finding.subject = text, severity, subject
        return finding

    @classmethod
    def of(cls, reason: object, severity: Severity | None = None, subject: str | None = None) -> Self:
        """Returns reason as a finding of severity about subject, keeping its help and output.

        reason: a text, a messages.Reason, or a Finding, whose own subject becomes part of the text.
        severity: if None, a Finding's own, else REFUSED.
        """
        if severity is None:
            severity = reason.severity if isinstance(reason, Finding) else Severity.REFUSED
        return cls(str(reason), severity, subject, messages.help_of(reason), messages.output_of(reason))

    @property
    def fatal(self) -> bool:
        """Tells whether this finding stops the command."""
        return self.severity.fatal


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
    """Outcome of an audit, or of the screening before a command runs, whose value is the exit status."""
    PASSED = 0
    REFUSED = 1
    FAILED = 3


class Report(NamedTuple):
    """Result of screening a command: what was found, and the verdict that follows from it."""
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
        """Returns the report of a single failure to look (Finding.of)."""
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
