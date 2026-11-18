"""This module defines the ProjectPatch class and the Substitution records it consists of. A ProjectPatch is a
set of changes that dockscreen makes to a compose project before running it; the classes apply the changes
and report them. They do not decide what to change.

Each change sets one key of one service. dockscreen reports every change it makes to the things it runs. A
change that alters the project's choice is a warning, and the others are info. dockscreen reports routine
changes of the same kind together, in one line that names their services (SubstitutionGroup), because the
line would be the same for each. A change with no notice and no group belongs to another change that is
reported, such as the HOME that comes with the default user.

A change that sets a value someone else chose names the origin of that value (origins), so that the policy
judges the value as that origin's. A change that only adds to the project's choice, or respells it, names no
origin.
"""

import copy
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from typing import Any, NamedTuple, Self

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.policy.notice import Notice, NoticeSeverity


class SubstitutionGroup(NamedTuple):
    """Record of a kind of routine change that dockscreen reports once, for all the services it changes. It
    holds the line and the advice on the next step.

    Attributes:
    - text: the line, with `{services}` where the names of the services go
    - help: the advice on the next step, or None
    """
    text: str
    help: str | None = None


class Substitution(NamedTuple):
    """Record of one change that dockscreen makes to a key of a compose service before running it. It
    serves to apply the change to the definition and to report it. It holds the key, its new value, the
    notice that reports it, and the origin of the value.

    Instances come from the functions that work out changes (hardening, the user rules, runoptions), in a
    ProjectPatch.

    Attributes:
    - service: the name of the service
    - key: the service key that is set
    - value: the new value of the key; it must not be changed in place, and ProjectPatch copies it into the
      definition
    - notice: the notice that reports the change on a line of its own, or None if the change has no line of
      its own. The notice is a warning if the change alters the project's choice, and info otherwise. It has
      no subject, because its subject is the change's service
    - group: the group that dockscreen reports the change with, or None
    - origin: the origin of the value; None to keep the origin of the key's previous value
    """
    service: str
    key: str
    value: Any
    notice: Notice | None = None
    group: SubstitutionGroup | None = None
    origin: Origin | None = None


@dataclass(frozen=True)
class ProjectPatch:
    """Value object for a set of changes to the services of a compose project. The changes are made together
    (apply_to) and reported together (notices). It holds the substitutions in the order they are made: of two
    substitutions that set the same key, the later substitution wins.

    Instances come from the functions that work out changes (hardening.changes, Policy.user_changes,
    runoptions.substitutions). The classmethod ProjectPatch.of makes a patch from substitutions, and
    `a + b` makes a patch with the substitutions of b after those of a. Iterating over a patch gives its
    substitutions.

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

    def apply_to(self, project: Project) -> Project:
        """Returns project with the substitutions made in its definition (apply_to_definition), and with the
        origins that they name (origins).
        """
        definition = self.apply_to_definition(project.definition)
        return project.with_definition(definition).with_origins(self.origins())

    def apply_to_definition(self, definition: dict[str, Any]) -> dict[str, Any]:
        """Returns a copy of the compose definition with the substitutions made, in their order."""
        changed_definition = copy.deepcopy(definition)
        for s in self.substitutions:
            changed_definition["services"][s.service][s.key] = copy.deepcopy(s.value)
        return changed_definition

    def origins(self) -> dict[str, dict[str, Origin]]:
        """Returns the origins of the values that the substitutions set, by service and key. A key gets the
        origin that its last substitution with an origin names. Keys without such a substitution are
        left out.
        """
        origins: dict[str, dict[str, Origin]] = {}
        for s in self.substitutions:
            if s.origin is not None:
                origins.setdefault(s.service, {})[s.key] = s.origin
        return origins

    def notices(self) -> list[Notice]:
        """Returns the notices that report the substitutions, for an audit or a run. First comes one notice
        for each substitution with a line of its own, about its service, in their order. Then comes one notice
        for each group (group_notices).
        """
        own_notices = [replace(s.notice,
                               subject=f"service {s.service}") for s in self.substitutions if s.notice]
        return [*own_notices, *self.group_notices()]

    def group_notices(self) -> list[Notice]:
        """Returns one notice for each group of the substitutions, naming its services, in the order in which
        the groups first appear.
        """
        services: dict[SubstitutionGroup, list[str]] = {}
        for s in self.substitutions:
            if s.group:
                services.setdefault(s.group, []).append(s.service)
        return [Notice(group.text.format(services=", ".join(dict.fromkeys(names))), NoticeSeverity.INFO,
                       help=group.help)
                for group, names in services.items()]
