"""This module defines the Substitution class and helpers for recording the changes dockscreen makes to a
compose config before running it, for applying them and for reporting them. It does not decide what to change.

Each change sets one key of one service. Everything dockscreen changes in what it runs is said: a change
that alters what the project chose is a warning, the others are info, and routine changes of the same
kind are reported together in one line that names their services (SubstitutionGroup), since the line would
be the same for each. A change with no text and no group is part of another that is reported, such as the HOME
that comes with the default user.

A change that sets a value someone else chose names where that value comes from (origins), so the policy
judges it as that origin's; one that only adds to, or respells, what the project chose names none.
"""

import copy
from collections.abc import Iterable
from dataclasses import replace
from typing import Any, NamedTuple

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen.notices import Notice, NoticeSeverity


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

    Instances come from the functions that work out changes (hardening, decisions, runoptions).

    Attributes:
    - service: the name of the service
    - key: the service key that is set
    - value: what the key is set to, which must not be changed in place; apply copies it into the definition
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


def individual(substitutions: Iterable[Substitution]) -> list[Notice]:
    """Describes the substitutions that are reported on their own line, one notice each, in their order,
    about their service.
    """
    return [replace(s.notice, subject=f"service {s.service}") for s in substitutions if s.notice]


def grouped(substitutions: Iterable[Substitution]) -> list[Notice]:
    """Describes the groups of the substitutions, one line each naming its services, in the order the groups
    first appear.
    """
    services: dict[SubstitutionGroup, list[str]] = {}
    for s in substitutions:
        if s.group:
            services.setdefault(s.group, []).append(s.service)
    return [Notice(group.text.format(services=", ".join(dict.fromkeys(names))), NoticeSeverity.INFO,
                   help=group.help)
            for group, names in services.items()]


def describe(substitutions: Iterable[Substitution]) -> list[Notice]:
    """Describes the substitutions for an audit or a run: the individual lines, then one per group."""
    found = list(substitutions)
    return [*individual(found), *grouped(found)]
