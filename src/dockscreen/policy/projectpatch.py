"""This module defines the ProjectPatch class, a set of changes dockscreen makes to a compose project before
running it, and the Substitution records it is made of, for applying the changes and reporting them. It does
not decide what to change.

Each change sets one key of one service. Everything dockscreen changes in what it runs is said: a change
that alters what the project chose is a warning, the others are info, and routine changes of the same
kind are reported together in one line that names their services (SubstitutionGroup), since the line would
be the same for each. A change with no notice and no group is part of another that is reported, such as the
HOME that comes with the default user.

A change that sets a value someone else chose names where that value comes from (origins), so the policy
judges it as that origin's; one that only adds to, or respells, what the project chose names none.
"""

import copy
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any, NamedTuple, Self

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.policy.notice import Notice, NoticeSeverity


class SubstitutionGroup(NamedTuple):
    """Record of a kind of routine change that is reported once for all the services it was made to. It holds
    the line and what to do about it.

    Attributes:
    - text: the line, with `{services}` where the names of the services go
    - help: what to do about it, or None
    """
    text: str
    help: str | None = None


class Substitution(NamedTuple):
    """Record of one change dockscreen makes to a key of a compose service before running it, for applying it
    to the definition and reporting it. It holds the key, its new value, the notice that reports it, and where
    the value comes from.

    Instances come from the functions that work out changes (hardening, the user rules, runoptions), in a
    ProjectPatch.

    Attributes:
    - service: the name of the service
    - key: the service key that is set
    - value: what the key is set to, which must not be changed in place; ProjectPatch copies it into the
      definition
    - notice: what it was and what dockscreen does, if it is reported on its own line, as a warning if it
      alters what the project chose, else info, and without a subject, which is its service; None if not
    - group: the group it is reported together with, or None
    - origin: where the value comes from; None for where the key's own value came from
    """
    service: str
    key: str
    value: Any
    notice: Notice | None = None
    group: SubstitutionGroup | None = None
    origin: Origin | None = None


@dataclass(frozen=True)
class ProjectPatch:
    """Value object for a set of changes to the services of a compose project, which are made together
    (applied_to) and reported together (notices). It holds the substitutions, in the order they are made: of
    two that set the same key, the later one wins.

    Instances come from the functions that work out changes (hardening.changes, Policy.user_changes,
    runoptions.substitutions); of makes one of substitutions, and `a + b` one with b's made after a's.
    Iterating over a patch gives its substitutions.

    Attributes:
    - substitutions: the substitutions, in their order
    """
    substitutions: tuple[Substitution, ...] = ()

    @classmethod
    def of(cls, substitutions: Iterable[Substitution]) -> Self:
        """Returns the patch of substitutions, in their order."""
        return cls(tuple(substitutions))

    def __add__(self, other: "ProjectPatch") -> "ProjectPatch":
        return ProjectPatch((*self.substitutions, *other.substitutions))

    def __iter__(self) -> Iterator[Substitution]:
        return iter(self.substitutions)

    def __len__(self) -> int:
        return len(self.substitutions)

    def applied_to(self, project: Project) -> Project:
        """Returns project with the substitutions made in its definition (applied_to_definition), and the
        origins they name (origins).
        """
        definition = self.applied_to_definition(project.definition)
        return project.with_definition(definition).with_origins(self.origins())

    def applied_to_definition(self, definition: dict[str, Any]) -> dict[str, Any]:
        """Returns a copy of the compose definition with the substitutions made, in their order."""
        changed = copy.deepcopy(definition)
        for s in self.substitutions:
            changed["services"][s.service][s.key] = copy.deepcopy(s.value)
        return changed

    def origins(self) -> dict[str, dict[str, Origin]]:
        """Returns where the keys the substitutions set get their values from, by service and key: from the
        origin of the last substitution of the key that names one. Keys that none names are left out.
        """
        found: dict[str, dict[str, Origin]] = {}
        for s in self.substitutions:
            if s.origin is not None:
                found.setdefault(s.service, {})[s.key] = s.origin
        return found

    def notices(self) -> list[Notice]:
        """Returns the notices that report the substitutions, for an audit or a run: one for each that is
        reported on its own line, about its service, in their order; then one for each group (group_notices).
        """
        own = [replace(s.notice, subject=f"service {s.service}") for s in self.substitutions if s.notice]
        return [*own, *self.group_notices()]

    def group_notices(self) -> list[Notice]:
        """Returns one notice for each group of the substitutions, naming its services, in the order the
        groups first appear.
        """
        services: dict[SubstitutionGroup, list[str]] = {}
        for s in self.substitutions:
            if s.group:
                services.setdefault(s.group, []).append(s.service)
        return [Notice(group.text.format(services=", ".join(dict.fromkeys(names))), NoticeSeverity.INFO,
                       help=group.help)
                for group, names in services.items()]
