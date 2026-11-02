"""This module defines the changes dockscreen makes to the services of a compose config before it runs it,
and how they are reported.

Each change sets one key of one service. Everything dockscreen changes in what it runs is said: a change
that alters what the project chose is notable, the others are routine, and routine changes of the same
kind are reported together in one line that names their services (Group), since the line would be the
same for each. A change with no text and no group is part of another that is reported, such as the HOME
that comes with the default user.

A change that sets a value someone else chose names where that value comes from (origins), so the policy
judges it as that origin's; one that only adds to, or respells, what the project chose names none.
"""

import copy
from collections.abc import Iterable
from typing import Any, NamedTuple

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.util import messages


class Group(NamedTuple):
    """Kind of routine change that is reported once for all the services it was made to: the line, with
    `{services}` where their names go, and what to do about it.
    """
    text: str
    help: str | None = None


class Substitution(NamedTuple):
    """Change dockscreen makes to one key of a compose service, with how it is reported."""
    service: str
    key: str
    value: Any                # what the key is set to
    text: str | None = None   # what it was and what dockscreen does, if it is reported on its own line
    notable: bool = False     # it alters what the project chose
    help: str | None = None   # what the project can do about it
    group: Group | None = None  # reported together with the others of its group
    origin: Origin | None = None  # where the value comes from; None: from where the key's own came from


def apply(config: dict[str, Any], substitutions: Iterable[Substitution]) -> dict[str, Any]:
    """Returns a copy of config with the substitutions made, in their order."""
    changed = copy.deepcopy(config)
    for s in substitutions:
        changed["services"][s.service][s.key] = copy.deepcopy(s.value)
    return changed


def applied(project: Project, substitutions: Iterable[Substitution]) -> Project:
    """Returns project with the substitutions made in its definition (apply), and the origins they name
    (origins).
    """
    found = list(substitutions)
    return project.with_definition(apply(project.definition, found)).with_origins(origins(found))


def origins(substitutions: Iterable[Substitution]) -> dict[str, dict[str, Origin]]:
    """Returns where the keys the substitutions set get their values from, by service and key: from the
    origin of the last substitution of the key that names one. Keys that none names are left out.
    """
    found: dict[str, dict[str, Origin]] = {}
    for s in substitutions:
        if s.origin is not None:
            found.setdefault(s.service, {})[s.key] = s.origin
    return found


def individual(substitutions: Iterable[Substitution]) -> list[messages.Marked]:
    """Describes the substitutions that are reported on their own line, one line each, in their order."""
    return [(messages.notable_change if s.notable else messages.routine_change)(
                f"service {s.service}: {s.text}", s.help)
            for s in substitutions if s.text]


def grouped(substitutions: Iterable[Substitution]) -> list[messages.Marked]:
    """Describes the groups of the substitutions, one line each naming its services, in the order the groups
    first appear.
    """
    services: dict[Group, list[str]] = {}
    for s in substitutions:
        if s.group:
            services.setdefault(s.group, []).append(s.service)
    return [messages.routine_change(group.text.format(services=", ".join(dict.fromkeys(names))), group.help)
            for group, names in services.items()]


def describe(substitutions: Iterable[Substitution]) -> list[messages.Marked]:
    """Describes the substitutions for an audit or a run: the individual lines, then one per group."""
    found = list(substitutions)
    return [*individual(found), *grouped(found)]
