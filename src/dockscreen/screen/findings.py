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

from dockscreen.host.dockerclient import DockerError
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


class Finding(messages.Message):
    """Value object for a statement about one subject of screening and how much it matters, which prints as a
    line marked by its severity (MARKS). Its string value is its text, after the subject and a colon if there
    is one, without the mark. It holds the subject, the severity and the docker error besides what a Message
    holds.

    The str base does not protect these attributes, so nothing changes them after construction. Build one with
    the constructor, or with of from a text, an error or another finding; replace builds a changed copy.

    Attributes:
    - subject: what it is about ("service web"), or None
    - severity: how much it matters
    - docker_error: the failure of docker that this finding reports, or None
    - text, help: as in Message
    """

    severity: Severity
    subject: str | None
    docker_error: DockerError | None

    def __new__(cls, text: str, severity: Severity = Severity.REFUSED, subject: str | None = None,
                help: str | None = None, docker_error: DockerError | None = None) -> Self:
        finding = str.__new__(cls, f"{subject}: {text}" if subject else text)
        finding.mark, finding.text = MARKS[severity], text
        finding.severity, finding.subject = severity, subject
        finding.help, finding.docker_error = help, docker_error
        return finding

    @property
    def shown(self) -> str:
        """Returns the subject and text, followed by the help if there is one and helpful mode is on."""
        return messages.with_help(str(self), self.help)

    @property
    def output(self) -> str | None:
        """Returns what docker printed about the failure (messages.HasOutput), or None."""
        return self.docker_error.output if self.docker_error else None

    @staticmethod
    def of(reason: object, severity: Severity | None = None, subject: str | None = None) -> "Finding":
        """Returns reason as a finding of severity about subject, keeping its help and docker error.

        Parameters:
        - reason: a text, an error, or a Finding, whose own subject becomes part of the text
        - severity: if None, a Finding's own, else REFUSED
        - subject: what it is about ("service web"); None to keep a Finding's own, or for none
        """
        if severity is None:
            severity = reason.severity if isinstance(reason, Finding) else Severity.REFUSED
        if isinstance(reason, Finding):
            docker_error = reason.docker_error
        else:
            docker_error = reason if isinstance(reason, DockerError) else None
        return Finding(str(reason), severity, subject, messages.help_of(reason), docker_error)

    def replace(self, *, text: str | None = None, help: str | None = None) -> "Finding":
        """Returns a copy of this finding with its text or its help changed, if given.

        Parameters:
        - text: the new text; None to keep it
        - help: the new help; None to keep it
        """
        return Finding(self.text if text is None else text, self.severity, self.subject,
                       self.help if help is None else help, self.docker_error)

    @property
    def fatal(self) -> bool:
        """Tells whether this finding stops the command."""
        return self.severity.fatal


def failure_of(error: BaseException, subject: str | None = None, help: str | None = None) -> Finding:
    """Returns the failure to look that error reports, about subject if given, with what to do about it
    (help) if given, and the error itself if it is a DockerError, whose output follows the finding.

    Parameters:
    - error: the error
    - subject: what it is about; None for none
    - help: what to do about it; None for nothing
    """
    return Finding.of(error, Severity.FAILED, subject).replace(help=help)


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

    Parameters:
    - reasons: what the policy refuses
    - origin: where the value comes from
    - trust: the origins whose values are taken as given
    - subject: what they are about; None for none
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

    Build one with of, or with refusal or failure for a single reason.

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
