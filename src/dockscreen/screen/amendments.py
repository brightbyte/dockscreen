"""This module defines the Amendment class and the function for applying amendments to a `docker run` or
`create` command line. It does not decide what to change: the rules do (Policy.user_amendments,
hardening.container_defaults).

An amendment puts arguments before the command line's own, so the options the command line gives itself
override it. It is the counterpart of a substitution (see substitutions), which sets a key of a compose
service instead.
"""

from collections.abc import Iterable, Sequence
from typing import NamedTuple

from dockscreen.screen.notices import Notice


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


def notices(amendments: Iterable[Amendment]) -> list[Notice]:
    """Returns the notices of the amendments that have one, in their order."""
    return [a.notice for a in amendments if a.notice]
