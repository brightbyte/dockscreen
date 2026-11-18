"""This module defines the UserDecision class, a record of a judgement of the user that a container would run
as. The method Policy.check_image returns a UserDecision.

The decision records the user's origin, like any other value's. The user can be:
- the image's own user (Origin.IMAGE), which the id rules judge;
- a user that the config file sets (Origin.CONFIG), for the image, the project or every image;
- the default user, for an image that would run as root (replaces_root); it is the config file's default
  user or dockscreen's own;
- a user that the command line chose; the image does not decide that user.

An image that dockscreen could not look at has no user, and so no origin.
"""

from typing import NamedTuple, Self

from dockscreen.model.image import Image, UserIdentity
from dockscreen.model.origin import Origin
from dockscreen.model.settings import NO_SECTION, SectionMatch
from dockscreen.policy.finding import Finding, Verdict
from dockscreen.policy.notice import Notice


class UserDecision(NamedTuple):
    """Record of a judgement of the user that a container would run as. It holds the origin of that user, the
    image, the notices and findings, the identity read from the image, and the user that dockscreen pins.

    Instances come from Policy.check_image, through Screener.assess for one container and through
    Screener.decide for a project. The classmethod UserDecision.failure returns a decision for an image that
    dockscreen could not look at.

    Attributes:
    - origin: where the user comes from; None if dockscreen could not look at the image
    - image: the image (Image)
    - notices: points worth a look that forbid nothing, such as an image section that does not apply, with
      the reason
    - findings: refusals and failures to look, which forbid running the container
    - identity: the ids read from the image, or None
    - user: the (uid, gid) dockscreen pins (pins_user), or None
    - section: which image section of the config file applied (SectionMatch)
    - home: the HOME to set for the default user that replaces root; "" leaves HOME alone, as when the
      command line or an env file chose a HOME (ImageInspection.is_home_chosen)
    - replaces_root: whether the default user runs instead of the image's root
    """
    origin: Origin | None
    image: Image
    notices: tuple[Notice, ...] = ()
    findings: tuple[Finding, ...] = ()
    identity: UserIdentity | None = None
    user: tuple[int, int] | None = None
    section: SectionMatch = NO_SECTION
    home: str = ""
    replaces_root: bool = False

    @classmethod
    def failure(cls, image: Image, reason: object) -> Self:
        """Returns a decision for an image that dockscreen could not look at, with reason as its finding."""
        return cls(None, image, (), (Finding.of(reason, Verdict.FAILED),))

    @property
    def is_refused(self) -> bool:
        """Tells whether the container must not run: refused, or not assessed at all."""
        return bool(self.findings)

    @property
    def has_failed(self) -> bool:
        """Tells whether the image could not be assessed at all."""
        return any(f.verdict is Verdict.FAILED for f in self.findings)

    @property
    def pins_user(self) -> bool:
        """Tells whether dockscreen decided the user and runs the image as that user, spelled as numbers. The
        user is the image's own, the config file's or the default user, but never a user that the command
        line chose.
        """
        return self.user is not None and not self.is_refused

    @property
    def is_accepted(self) -> bool:
        """Tells whether the image runs as its decided user (pins_user) without replacing its root. That user
        is the image's own user, accepted by the rules, or the user that the config file sets for it.
        """
        return self.pins_user and not self.replaces_root

    @property
    def pinned_user(self) -> tuple[int, int]:
        """Returns the (uid, gid) dockscreen decided; only for a decision that pins_user."""
        assert self.user is not None, f"a decision of a user from {self.origin} pins none"
        return self.user
