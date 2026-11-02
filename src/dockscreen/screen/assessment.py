"""This module defines the judgement of the user a container would run as (Assessment), which the policy
makes (Policy.check_image).

Where that user comes from is an origin like any other value's: the image's own user (Origin.IMAGE),
judged by the id rules; one the config file sets (Origin.CONFIG), for the image, the project or every one;
the default user for an image that would run as root (replaces_root), the config file's or dockscreen's
own; or one the command line chose, which the image does not decide. An image that could not be looked at
has no user, and so no origin.
"""

from typing import NamedTuple, Self

from dockscreen.model.image import Identity, Image
from dockscreen.model.origin import Origin
from dockscreen.screen.findings import Finding, Severity


class Assessment(NamedTuple):
    """Judgement of the user a container would run as: where the user comes from (origin, None if the image
    could not be looked at; and whether it is the default user instead of the image's root, replaces_root),
    the image, what was found (refusals, failures to look, and notable findings), the identity read from the
    image, and the user dockscreen pins.
    """
    origin: Origin | None
    image: Image
    findings: tuple[Finding, ...] = ()
    identity: Identity | None = None
    user: tuple[int, int] | None = None  # the (uid, gid) it runs as, when dockscreen decided it (pins_user)
    section: str | None = None     # the repository whose image section applied, if one did
    home: str = ""                 # the HOME to set for the default user that replaces root; "": leave it
    replaces_root: bool = False    # the image would run as root: the default user instead

    @classmethod
    def failure(cls, image: Image, reason: object) -> Self:
        """Returns the assessment of an image that could not be looked at, for reason."""
        return cls(None, image, (Finding.of(reason, Severity.FAILED),))

    @property
    def reasons(self) -> list[Finding]:
        """Returns the findings that forbid running the container: refusals, or failures to look."""
        return [f for f in self.findings if f.fatal]

    @property
    def notes(self) -> list[Finding]:
        """Returns what is worth a look but forbids nothing: an image section that does not apply, and why."""
        return [f for f in self.findings if not f.fatal]

    @property
    def refused(self) -> bool:
        """Tells whether the container must not run: refused, or not assessed at all."""
        return bool(self.reasons)

    @property
    def failed(self) -> bool:
        """Tells whether the image could not be assessed at all."""
        return any(f.severity is Severity.FAILED for f in self.findings)

    @property
    def pins_user(self) -> bool:
        """Tells whether dockscreen decided the user, and runs the image as it, spelled as numbers: the
        image's own, the config file's, or the default user; not one the command line chose.
        """
        return self.user is not None and not self.refused

    @property
    def accepted(self) -> bool:
        """Tells whether the image runs as the user decided for it without replacing its root (pins_user):
        its own user, accepted, or the one the config file sets for it.
        """
        return self.pins_user and not self.replaces_root

    @property
    def pinned_user(self) -> tuple[int, int]:
        """Returns the (uid, gid) dockscreen decided; only for an assessment that pins_user."""
        assert self.user is not None, f"an assessment of a user from {self.origin} pins none"
        return self.user
