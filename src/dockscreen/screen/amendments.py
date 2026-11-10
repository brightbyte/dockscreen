"""This module defines the Amendment class and the functions for applying amendments to a `docker run` or
`create` command line, and for the amendment that runs a container as the user decided for its image. It does
not decide what to change.

An amendment puts arguments before the command line's own, so the options the command line gives itself
override it. It is the counterpart of a substitution (see substitutions), which sets a key of a compose
service instead.
"""

from collections.abc import Iterable, Sequence
from typing import NamedTuple

from dockscreen.screen.decisions import default_home
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.userdecision import UserDecision
from dockscreen.screen.userdecisionview import CHOOSE_HINT, instead_of_root
from dockscreen.util import ids


class Amendment(NamedTuple):
    """Record of arguments dockscreen puts before those of a `docker run` or `create` command line, and the
    notice that reports them.

    Attributes:
    - args: the arguments
    - notice: what dockscreen does, or None if it is part of another amendment that is reported
    """
    args: tuple[str, ...]
    notice: Notice | None = None


def applied(args: Sequence[str], amendments: Iterable[Amendment]) -> list[str]:
    """Returns args with the arguments of the amendments before them, in the amendments' order."""
    return [*(arg for a in amendments for arg in a.args), *args]


def pinned_user(decision: UserDecision, image: str) -> Amendment:
    """Returns the amendment that runs the container as the user decision pins (UserDecision.pins_user), as
    numbers: a warning if that user is the default one instead of the image's root, else info.

    Parameters:
    - decision: the decision of the container's image, which pins a user
    - image: the image, as the command line names it
    """
    user = ids.format_user(decision.pinned_user)
    args = (f"--user={user}",)
    if not decision.replaces_root:
        return Amendment(args, Notice(f"image {image} runs as {user}, passed to docker as numbers",
                                      NoticeSeverity.INFO))
    home = default_home(decision.pinned_user, decision.home)
    return Amendment(args, Notice(
        instead_of_root(decision), NoticeSeverity.WARNING,
        help=f"the default user replaces root; {CHOOSE_HINT}; files and volumes set up for root may not be "
        "accessible to it" + (f", and its HOME is set to {home} unless you set it" if home else "")))
