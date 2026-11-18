"""This module defines the Finding class, for a problem that screening finds and that stops a command.
Problems that do not stop the command are notices (notice), and the module report holds the verdict that
follows from the findings.

A finding states one thing about one subject (a service, an image, a container, the command line): the
reason that the command must not run. Its verdict says which kind of reason it is. Refused means that the
policy says no. Failed means that screening could not get far enough to judge: docker, the image or the
compose config was not there, or pulling or building failed. A refusal is about the project, the image or
the command line. A failure is about getting to them, and may go away when the user tries again.

The verdict of a whole screening is the worst of its findings, and the exit status of an audit. Exit status 2
is left for usage errors.
"""

import enum
from collections.abc import Iterable
from dataclasses import dataclass, replace

from dockscreen.host.docker import DockerError
from dockscreen.model.origin import Origin
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.util import messages


class Verdict(enum.IntEnum):
    """Enum of the outcomes of an audit, or of the screening before a command runs. Its value is the exit
    status, and the worse outcome has the larger value.
    """
    PASSED = 0
    REFUSED = 1
    FAILED = 3


@dataclass(frozen=True)
class Finding:
    """Value object for a statement about one subject of screening, giving the reason that the command must
    not run. It prints as a line marked as an error. It holds the text, the verdict, the subject, the advice
    on the next step, and the docker error.

    Its string value is the text, after the subject and a colon if there is one. Build a finding with the
    constructor, or with the static method Finding.of from a text, an error or another finding. The methods
    with_text and with_help build a changed copy. Two findings are equal if all of these are equal.

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
    def display_text(self) -> str:
        """Returns the subject and text, followed by the help if there is one and helpful mode is on."""
        return messages.with_help(str(self), self.help)

    @property
    def output(self) -> str | None:
        """Returns what docker printed about the failure (messages.HasOutput), or None."""
        return self.docker_error.output if self.docker_error else None

    @staticmethod
    def of(reason: object, verdict: Verdict | None = None, subject: str | None = None) -> "Finding":
        """Returns reason as a finding with verdict, about subject. The finding keeps the help and the docker
        error of reason.

        Parameters:
        - reason: a text, an error, or a Finding, whose own subject becomes part of the text
        - verdict: the verdict; if None, the verdict of reason if it is a Finding, else REFUSED
        - subject: what it is about ("service web"); None to keep the subject of reason if it is a Finding,
          or for no subject
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
        """Returns a copy of this finding with help as what to do about it; None for no help."""
        return replace(self, help=help)

    def with_subject(self, subject: str) -> "Finding":
        """Returns a copy of this finding about subject. This finding's own subject becomes part of the
        text.
        """
        return Finding.of(self, subject=subject)


# A check of the policy returns a list of these: findings, and notices for problems with a trusted value.
ReportEntry = Finding | Notice


def failure_of(error: BaseException, subject: str | None = None, help: str | None = None) -> Finding:
    """Returns the failure to look that error reports, as a finding about subject, with help. Both are
    optional. If error is a DockerError, the finding keeps it, and its output follows the finding.

    Parameters:
    - error: the error
    - subject: what it is about; None for no subject
    - help: what to do about it; None for no help
    """
    return Finding.of(error, Verdict.FAILED, subject).with_help(help)


def with_subject(entries: Iterable[ReportEntry], subject: str) -> list[ReportEntry]:
    """Returns each of entries as an entry about subject, with its own verdict or severity. The entry's own
    subject becomes part of its text.
    """
    return [f.with_subject(subject) for f in entries]


def refusals(reasons: Iterable[object], subject: str | None = None) -> list[Finding]:
    """Returns each of reasons as a refusal (Finding.of), about subject if given."""
    return [Finding.of(r, Verdict.REFUSED, subject) for r in reasons]


def failures(reasons: Iterable[object], subject: str | None = None) -> list[Finding]:
    """Returns each of reasons as a failure to look (Finding.of), about subject if given."""
    return [Finding.of(r, Verdict.FAILED, subject) for r in reasons]


def judge(reasons: Iterable[object], origin: Origin, trust: Iterable[Origin], subject: str | None = None
           ) -> list[ReportEntry]:
    """Returns each of reasons as a refusal. The reasons are the policy's objections to a value from origin.
    If origin is in trust, the policy takes its values as given, and each reason becomes a warning instead.

    Parameters:
    - reasons: what the policy refuses
    - origin: where the value comes from
    - trust: the origins whose values are taken as given
    - subject: what they are about; None for no subject
    """
    if origin in trust:
        return [Notice(str(r), NoticeSeverity.WARNING, subject, messages.help_of(r)) for r in reasons]
    return [*refusals(reasons, subject)]
