"""This module provides functions for working out, as substitutions, the defaults to add to every service of a
compose config, with the ids on this host for the user names in it (Policy.resolve_user_names); and, as an
amendment, the same defaults for a container that `docker run` or `create` makes.

A project does not have to set these itself: a service without `cap_drop: [ALL]`
or `no-new-privileges` gets them. A project cannot weaken them, because adding
`cap_add` or `no-new-privileges:false` is still refused by the policy. The
changes are substitutions (see substitutions), reported by `audit` and before a run.
"""

import json
from typing import Any

from dockscreen.model.origin import Origin
from dockscreen.screen.amendments import Amendment
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.policy import Policy
from dockscreen.screen.rules.service import CAP_DROP, SECURITY_OPT, drops_all, has_no_new_privileges
from dockscreen.screen.substitutions import Substitution, SubstitutionGroup


def changes(config: dict[str, Any], policy: Policy) -> list[Substitution]:
    """Returns the substitutions that add dockscreen's defaults to every service of config and resolve user
    names to ids (Policy.resolve_user_names).

    Parameters:
    - config: the project's resolved config
    - policy: the policy whose rules resolve the names
    """
    found = []
    for name, service in (config.get("services") or {}).items():
        found += policy.resolve_user_names(name, service or {})
        found += _defaults(name, service or {})
    return found


def container_defaults() -> Amendment:
    """Returns the amendment that adds the defaults to a container that `docker run` or `create` makes, before
    the command line's own options, which may override them.
    """
    args = (f"--cap-drop={CAP_DROP}", f"--security-opt={SECURITY_OPT}")
    notice = Notice(f"added {' '.join(args)}", NoticeSeverity.INFO, help=CONTAINER_DEFAULTS_HELP)
    return Amendment(args, notice)


def _defaults(name: str, service: dict[str, Any]) -> list[Substitution]:
    """Returns the substitutions that add cap_drop ALL and no-new-privileges where the service lacks them.

    Where the service sets nothing, they are routine and reported for all services in one line; where it
    sets the key itself, dockscreen extends its choice, which is notable.
    """
    found = []
    if not drops_all(service.get("cap_drop")):
        found.append(_default(name, "cap_drop", service.get("cap_drop"), CAP_DROP, f"lacks {CAP_DROP}"))
    if not has_no_new_privileges(service.get("security_opt")):
        found.append(_default(name, "security_opt", service.get("security_opt"), SECURITY_OPT,
                              "lacks no-new-privileges"))
    return found


def _default(name: str, key: str, declared: list[Any] | None, value: str, lacks: str) -> Substitution:
    """Returns the substitution that adds value to the list the service declared for key, if any; the key
    then still holds what the project chose, and is judged as the project's.
    """
    if not declared:
        return Substitution(name, key, [value], group=DEFAULTS, origin=Origin.DOCKSCREEN)
    text = f"{key} {lacks}; added {json.dumps([value])}"
    notice = Notice(text, NoticeSeverity.WARNING, help=NOT_REMOVABLE)
    return Substitution(name, key, [*declared, value], notice)


NOT_REMOVABLE = "dockscreen always adds it, and cap_add is refused: a service that needs more cannot run"
DEFAULTS_HELP = ("a service that needs a capability or a setuid program fails, and cap_add is refused: "
                 "it cannot run under dockscreen")
CONTAINER_DEFAULTS_HELP = ("a program that needs a capability or setuid fails: add --cap-add or "
                           "--security-opt yourself, which override these")


DEFAULTS = SubstitutionGroup(
    f'added cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] where missing, '
    "in services {services}", DEFAULTS_HELP)


def defaults_note() -> str:
    """Returns one general sentence about the defaults for generated files, instead of a line per service."""
    return (f'dockscreen also adds cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] to every '
            "service that lacks them, resolves user and group names to ids on this host, and runs a "
            "service that sets no user as the configured default user when its image would run as root, "
            "so these are not repeated here")
