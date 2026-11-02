"""This module defines the judgement of the user a container would run as (Assessment), which the policy
makes (Policy.check_image), and where that user comes from (Kind).
"""

import enum
from typing import NamedTuple, Self

from dockscreen.model.identity import Identity
from dockscreen.model.image import Image
from dockscreen.screen.findings import Finding, Severity


class Kind(enum.StrEnum):
    """Source of the user a container runs as, as the decision about it found it."""
    EXPLICIT = "explicit"      # the command line or dockscreen chose the user, not the image
    CONFIGURED = "configured"  # the config file names the user, for this image, project or every one
    IMAGE = "image"            # the image's own user, accepted or not (Assessment.refused)
    FALLBACK = "fallback"      # the image would run as root: the default user instead


class Assessment(NamedTuple):
    """Judgement of the user a container would run as: where the user comes from, the image, what was found
    (refusals, failures to look, and notable findings), the identity read from the image, and the user
    dockscreen pins.
    """
    kind: Kind
    image: Image
    findings: tuple[Finding, ...] = ()
    identity: Identity | None = None
    user: tuple[int, int] | None = None  # the (uid, gid) it runs as, when dockscreen decided it (pins_user)
    section: str | None = None     # the repository whose image section applied, if one did
    home: str = ""                 # the HOME to set for the default user that replaces root; "": leave it

    @classmethod
    def failure(cls, image: Image, reason: object) -> Self:
        """Returns the assessment of an image that could not be looked at, for reason."""
        return cls(Kind.IMAGE, image, (Finding.of(reason, Severity.FAILED),))

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
        """Tells whether dockscreen decided the user, and runs the image as it, spelled as numbers."""
        return self.kind is not Kind.EXPLICIT and not self.refused

    @property
    def pinned_user(self) -> tuple[int, int]:
        """Returns the (uid, gid) dockscreen decided; only for an assessment that pins_user."""
        assert self.user is not None, f"a {self.kind} assessment pins no user"
        return self.user

    @property
    def replaces_image_user(self) -> bool:
        """Tells whether the user dockscreen decided differs from the one the image chose."""
        return self.kind in (Kind.CONFIGURED, Kind.FALLBACK) and not self.refused

