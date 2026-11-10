"""This module defines the CommandLinePatch class, a set of changes dockscreen makes to a `docker run` or
`create` command line before docker gets it, and the Amendment records it is made of, for applying the changes
and reporting them. It does not decide what to change: the rules do (Policy.user_amendments,
hardening.container_defaults).

An amendment puts arguments before the command line's own, so the options the command line gives itself
override it. It is the counterpart of a substitution (see projectpatch), which sets a key of a compose
service instead.
"""

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import NamedTuple, Self

from dockscreen.screen.notice import Notice


class Amendment(NamedTuple):
    """Record of arguments dockscreen puts before those of a `docker run` or `create` command line, and the
    notice that reports them.

    Attributes:
    - args: the arguments
    - notice: what dockscreen does, or None if it is part of another amendment that is reported
    """
    args: tuple[str, ...]
    notice: Notice | None = None


@dataclass(frozen=True)
class CommandLinePatch:
    """Value object for a set of changes to the arguments of a `docker run` or `create` command line, which
    are made together (applied_to) and reported together (notices). It holds the amendments, in their order.

    Instances come from the rules and hardening (Policy.user_amendments, hardening.container_defaults); of
    makes one of amendments, and `a + b` one with b's arguments after a's. Iterating over a patch gives its
    amendments.

    Attributes:
    - amendments: the amendments, in their order
    """
    amendments: tuple[Amendment, ...] = ()

    @classmethod
    def of(cls, amendments: Iterable[Amendment]) -> Self:
        """Returns the patch of amendments, in their order."""
        return cls(tuple(amendments))

    def __add__(self, other: "CommandLinePatch") -> "CommandLinePatch":
        return CommandLinePatch((*self.amendments, *other.amendments))

    def __iter__(self) -> Iterator[Amendment]:
        return iter(self.amendments)

    def __len__(self) -> int:
        return len(self.amendments)

    @property
    def args(self) -> tuple[str, ...]:
        """Returns the arguments of the amendments, in their order."""
        return tuple(arg for a in self.amendments for arg in a.args)

    def applied_to(self, args: Sequence[str]) -> list[str]:
        """Returns args with the arguments of the amendments before them."""
        return [*self.args, *args]

    def notices(self) -> list[Notice]:
        """Returns the notices of the amendments that have one, in their order."""
        return [a.notice for a in self.amendments if a.notice]
