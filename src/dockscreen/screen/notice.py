"""This module defines the Notice class, for what screening reports without stopping the command: what
dockscreen changes in what it runs, and what is worth a look. A Notice never judges anything; what is
refused, or could not be looked at, is a Finding (finding).

A notice is info if it rarely changes how anything runs, a warning if it can.
"""

import enum
from dataclasses import dataclass, replace

from dockscreen.util import messages


class NoticeSeverity(enum.Enum):
    """Enum of how much a notice matters to whoever runs the command."""
    INFO = "info"        # rarely changes how anything runs
    WARNING = "warning"  # worth a look, it can change how something runs


# The mark a notice is shown with, by its severity.
MARKS = {NoticeSeverity.INFO: messages.ROUTINE, NoticeSeverity.WARNING: messages.WARN}


@dataclass(frozen=True)
class Notice:
    """Value object for a statement about one subject of screening that stops nothing, which prints as a line
    marked by its severity (MARKS). It holds the text, the severity, the subject and what to do about it.

    Its string value is the text, after the subject and a colon if there is one. Build one with the
    constructor; with_text and with_help build a changed copy. Two notices are equal if all of that is.

    Attributes:
    - text: what it says, without the subject
    - severity: how much it matters
    - subject: what it is about ("service web"), or None
    - help: what to do about it, shown only in helpful mode (messages.set_helpful), or None
    """

    text: str
    severity: NoticeSeverity = NoticeSeverity.INFO
    subject: str | None = None
    help: str | None = None

    def __str__(self) -> str:
        return f"{self.subject}: {self.text}" if self.subject else self.text

    @property
    def mark(self) -> messages.Mark:
        """Returns the mark of its line (messages.HasMark)."""
        return MARKS[self.severity]

    @property
    def shown(self) -> str:
        """Returns the subject and text, followed by the help if there is one and helpful mode is on."""
        return messages.with_help(str(self), self.help)

    def with_text(self, text: str) -> "Notice":
        """Returns a copy of this notice with text as its text, after the same subject."""
        return replace(self, text=text)

    def with_help(self, help: str | None) -> "Notice":
        """Returns a copy of this notice with help as what to do about it; None for nothing."""
        return replace(self, help=help)

    def about(self, subject: str) -> "Notice":
        """Returns a copy of this notice about subject, which its own subject becomes part of the text of."""
        return replace(self, text=str(self), subject=subject)
