"""This module defines the CommandLinePatch class and the Amendment records it consists of. A CommandLinePatch
is a set of changes that dockscreen makes to a `docker run` or `create` command line before docker gets it;
the classes apply the changes and report them. They do not decide what to change; the rules do
(Policy.user_amendments, hardening.container_defaults).

An amendment puts arguments before the command line's own arguments, so that the command line's own options
override the amendment. It is the counterpart of a substitution (see projectpatch), which sets a key of a
compose service instead.
"""

from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from typing import NamedTuple, Self

from dockscreen.policy.notice import Notice


class Amendment(NamedTuple):
    """Record of arguments dockscreen puts before those of a `docker run` or `create` command line, and the
    notice that reports them.

    Attributes:
    - args: the arguments
    - notice: the notice that reports the amendment, or None if the notice of another amendment reports
      this amendment too
    """
    args: tuple[str, ...]
    notice: Notice | None = None


@dataclass(frozen=True)
class CommandLinePatch:
    """Value object for a set of changes to the arguments of a `docker run` or `create` command line. The
    changes are made together (apply_to) and reported together (notices). It holds the amendments, in their
    order.

    Instances come from the rules and hardening (Policy.user_amendments, hardening.container_defaults). The
    classmethod CommandLinePatch.of makes a patch from amendments, and `a + b` makes a patch with the
    arguments of b after those of a. Iterating over a patch gives its amendments.

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

    def apply_to(self, args: Sequence[str]) -> list[str]:
        """Returns args, preceded by the arguments of the amendments."""
        return [*self.args, *args]

    def notices(self) -> list[Notice]:
        """Returns the notices of the amendments that have a notice, in their order."""
        return [a.notice for a in self.amendments if a.notice]
