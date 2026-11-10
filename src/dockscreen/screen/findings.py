"""This module defines the Finding class, for what screening finds that stops a command (see notices for what
it reports without stopping it, and report for the verdict that follows from the findings).

A finding says one thing about one subject (a service, an image, a container, the command line) and why the
command must not run, as the verdict it makes. Refused means the policy says no. Failed means screening could
not get far enough to judge: docker, the image or the compose config was not there, or pulling or building
failed. A refusal is about the project, image or command line; a failure is about getting to them, and may go
away when retried.

The verdict of a whole screening is the worst of its findings, and the exit status of an audit. Exit status 2
is left for usage errors.
"""

import enum
from collections.abc import Iterable
from dataclasses import dataclass, replace

from dockscreen.host.dockerclient import DockerError
from dockscreen.model.origin import Origin
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.util import messages


class Verdict(enum.IntEnum):
    """Enum of the outcomes of an audit, or of the screening before a command runs. Its value is the exit
    status, and the worse outcome has the larger one.
    """
    PASSED = 0
    REFUSED = 1
    FAILED = 3


@dataclass(frozen=True)
class Finding:
    """Value object for a statement about one subject of screening and why the command must not run, which
    prints as a line marked as an error. It holds the text, the verdict, the subject, what to do about it and
    the docker error.

    Its string value is the text, after the subject and a colon if there is one. Build one with the
    constructor, or with of from a text, an error or another finding; with_text and with_help build a changed
    copy. Two findings are equal if all of that is.

    Attributes:
    - text: what it says, without the subject
    - verdict: REFUSED or FAILED, never PASSED, which is no reason to stop
    - subject: what it is about ("service web"), or None
    - help: what to do about it, shown only in helpful mode (messages.set_helpful), or None
    - docker_error: the failure of docker that this finding reports, or None
    """

    text: str
    verdict: Verdict = Verdict.REFUSED
    subject: str | None = None
    help: str | None = None
    docker_error: DockerError | None = None

    def __post_init__(self) -> None:
        if self.verdict is Verdict.PASSED:
            raise ValueError("a finding stops the command, so its verdict cannot be PASSED")

    def __str__(self) -> str:
        return f"{self.subject}: {self.text}" if self.subject else self.text

    @property
    def mark(self) -> messages.Mark:
        """Returns the mark of its line (messages.HasMark)."""
        return messages.BAD

    @property
    def shown(self) -> str:
        """Returns the subject and text, followed by the help if there is one and helpful mode is on."""
        return messages.with_help(str(self), self.help)

    @property
    def output(self) -> str | None:
        """Returns what docker printed about the failure (messages.HasOutput), or None."""
        return self.docker_error.output if self.docker_error else None

    @staticmethod
    def of(reason: object, verdict: Verdict | None = None, subject: str | None = None) -> "Finding":
        """Returns reason as a finding with verdict about subject, keeping its help and docker error.

        Parameters:
        - reason: a text, an error, or a Finding, whose own subject becomes part of the text
        - verdict: if None, a Finding's own, else REFUSED
        - subject: what it is about ("service web"); None to keep a Finding's own, or for none
        """
        if verdict is None:
            verdict = reason.verdict if isinstance(reason, Finding) else Verdict.REFUSED
        if isinstance(reason, Finding):
            docker_error = reason.docker_error
        else:
            docker_error = reason if isinstance(reason, DockerError) else None
        return Finding(str(reason), verdict, subject, messages.help_of(reason), docker_error)

    def with_text(self, text: str) -> "Finding":
        """Returns a copy of this finding with text as its text, after the same subject."""
        return replace(self, text=text)

    def with_help(self, help: str | None) -> "Finding":
        """Returns a copy of this finding with help as what to do about it; None for nothing."""
        return replace(self, help=help)

    def about(self, subject: str) -> "Finding":
        """Returns a copy of this finding about subject, which its own subject becomes part of the text of."""
        return Finding.of(self, subject=subject)


# What a check of the policy returns a list of: findings, and notices for what a trusted value gets.
Reportable = Finding | Notice


def failure_of(error: BaseException, subject: str | None = None, help: str | None = None) -> Finding:
    """Returns the failure to look that error reports, about subject if given, with what to do about it
    (help) if given, and the error itself if it is a DockerError, whose output follows the finding.

    Parameters:
    - error: the error
    - subject: what it is about; None for none
    - help: what to do about it; None for nothing
    """
    return Finding.of(error, Verdict.FAILED, subject).with_help(help)


def about(found: Iterable[Reportable], subject: str) -> list[Reportable]:
    """Returns each of found as one about subject, which its own subject becomes part of the text of, with
    its own verdict or severity.
    """
    return [f.about(subject) for f in found]


def refusals(reasons: Iterable[object], subject: str | None = None) -> list[Finding]:
    """Returns each of reasons as a refusal (Finding.of), about subject if given."""
    return [Finding.of(r, Verdict.REFUSED, subject) for r in reasons]


def failures(reasons: Iterable[object], subject: str | None = None) -> list[Finding]:
    """Returns each of reasons as a failure to look (Finding.of), about subject if given."""
    return [Finding.of(r, Verdict.FAILED, subject) for r in reasons]


def judged(reasons: Iterable[object], origin: Origin, trust: Iterable[Origin], subject: str | None = None
           ) -> list[Reportable]:
    """Returns each of reasons, what the policy refuses in a value from origin, as a refusal; or as a
    warning if origin is in trust, whose values are taken as given.

    Parameters:
    - reasons: what the policy refuses
    - origin: where the value comes from
    - trust: the origins whose values are taken as given
    - subject: what they are about; None for none
    """
    if origin in trust:
        return [Notice(str(r), NoticeSeverity.WARNING, subject, messages.help_of(r)) for r in reasons]
    return refusals(reasons, subject)
