"""This module provides functions for working out the defaults to add to every service of a compose config.
They come as substitutions, together with the substitutions that replace the user names in the config by
their ids on this host (Policy.resolve_user_names). The module also provides the same defaults as an
amendment, for a container that `docker run` or `create` makes.

A project does not have to set these itself: a service without `cap_drop: [ALL]` or `no-new-privileges`
gets them. A project cannot weaken them either, because the policy still refuses `cap_add` and
`no-new-privileges:false`. The changes are a ProjectPatch (see projectpatch); `audit` reports them, and so
does every run.

The defaults are the second line of defense behind the user rules. no-new-privileges keeps a setuid binary of
the image from making the checked user root. Without capabilities, a process that became root anyway cannot
override the permissions of mounted host files (rules.servicerules, CAP_DROP).
"""

import json
from typing import Any

from dockscreen.model.origin import Origin
from dockscreen.policy.commandlinepatch import Amendment, CommandLinePatch
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.policy import Policy
from dockscreen.policy.projectpatch import ProjectPatch, Substitution, SubstitutionGroup
from dockscreen.policy.rules.servicerules import CAP_DROP, SECURITY_OPT, drops_all, has_no_new_privileges


def changes(config: dict[str, Any], policy: Policy) -> ProjectPatch:
    """Returns the patch that adds dockscreen's defaults to every service of config. The patch also resolves
    user names to ids (Policy.resolve_user_names).

    Parameters:
    - config: the project's resolved config
    - policy: the policy whose rules resolve the names
    """
    patch = ProjectPatch()
    for name, service in (config.get("services") or {}).items():
        service = service or {}
        default_patch = ProjectPatch.of(_default_substitutions(name, service))
        patch += policy.resolve_user_names(name, service) + default_patch
    return patch


def container_defaults() -> CommandLinePatch:
    """Returns the patch that adds the defaults to a container that `docker run` or `create` makes. The patch
    puts the defaults before the command line's own options, so that those options can override the
    defaults.
    """
    args = (f"--cap-drop={CAP_DROP}", f"--security-opt={SECURITY_OPT}")
    notice = Notice(f"added {' '.join(args)}", NoticeSeverity.INFO, help=CONTAINER_DEFAULTS_HELP)
    return CommandLinePatch.of([Amendment(args, notice)])


def _default_substitutions(name: str, service: dict[str, Any]) -> list[Substitution]:
    """Returns the substitutions that add cap_drop ALL and no-new-privileges where the service lacks them.

    Where the service sets nothing, the substitutions are routine, and dockscreen reports them for all
    services in one line. Where the service sets the key itself, dockscreen extends the service's choice,
    which is notable.
    """
    substitutions = []
    if not drops_all(service.get("cap_drop")):
        substitutions.append(_default_substitution(name, "cap_drop", service.get("cap_drop"), CAP_DROP,
                                                   f"lacks {CAP_DROP}"))
    if not has_no_new_privileges(service.get("security_opt")):
        substitutions.append(_default_substitution(name, "security_opt", service.get("security_opt"),
                                                   SECURITY_OPT, "lacks no-new-privileges"))
    return substitutions


def _default_substitution(name: str, key: str, declared_values: list[Any] | None, value: str,
                          lacks: str) -> Substitution:
    """Returns the substitution that adds value to the list that the service declared for key, if any.
    The key then still holds the project's choice, and the policy judges it as the project's.
    """
    if not declared_values:
        return Substitution(name, key, [value], group=DEFAULTS, origin=Origin.DOCKSCREEN)
    text = f"{key} {lacks}; added {json.dumps([value])}"
    notice = Notice(text, NoticeSeverity.WARNING, help=NOT_REMOVABLE_REASON)
    return Substitution(name, key, [*declared_values, value], notice)


NOT_REMOVABLE_REASON = ("dockscreen always adds it, and cap_add is refused: a service that needs more cannot "
                        "run")
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
