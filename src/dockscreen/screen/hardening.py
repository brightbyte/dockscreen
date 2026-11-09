"""This module provides functions for working out, as substitutions, the defaults to add to every service of a
compose config, and the ids on this host for the user names in it.

A project does not have to set these itself: a service without `cap_drop: [ALL]`
or `no-new-privileges` gets them. Names in `user:` and hook users are resolved
to ids on this host, so the generated file never asks the image to resolve a name; the policy
then checks the ids, and refuses a name that does not exist here. A project cannot weaken them, because adding
`cap_add` or `no-new-privileges:false` is still refused by the policy. The
changes are substitutions (see substitutions), reported by `audit` and before a run.
"""

import json
from typing import Any

from dockscreen.host import hostusers
from dockscreen.model.origin import Origin
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.rules.service import CAP_DROP, SECURITY_OPT, drops_all, has_no_new_privileges
from dockscreen.screen.substitutions import Substitution, SubstitutionGroup
from dockscreen.util import ids


def changes(config: dict[str, Any], accounts: hostusers.HostAccounts) -> list[Substitution]:
    """Returns the substitutions that add dockscreen's defaults to every service of config and resolve user
    names to ids.

    Parameters:
    - config: the project's resolved config
    - accounts: the users and groups to resolve names with (hostusers.HostAccounts)
    """
    found = []
    for name, service in (config.get("services") or {}).items():
        found += _resolve_user_names(name, service or {}, accounts)
        found += _defaults(name, service or {})
    return found


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


def _resolve_user_names(name: str, service: dict[str, Any],
                        accounts: hostusers.HostAccounts) -> list[Substitution]:
    """Returns the substitutions that replace names in the service's user and hook users by their ids."""
    found = []
    if service.get("user"):
        resolved = _resolve_spec(service["user"], accounts)
        if resolved != service["user"]:
            message = _resolved_message("user", service["user"], resolved)
            found.append(Substitution(name, "user", resolved, _resolved_notice(message)))
    for key in ("post_start", "pre_stop"):
        hooks = service.get(key) or []
        resolved_hooks = [_with_resolved_user(hook, accounts) for hook in hooks]
        for hook, resolved_hook in zip(hooks, resolved_hooks):
            if resolved_hook is not hook:
                message = _resolved_message(f"{key} user", hook["user"], resolved_hook["user"])
                found.append(Substitution(name, key, resolved_hooks, _resolved_notice(message)))
    return found


def _resolved_notice(message: str) -> Notice:
    """Returns the notice that message, a name resolved to ids, is reported by."""
    return Notice(message, NoticeSeverity.INFO, help=RESOLVE_HELP)


def _with_resolved_user(hook: Any, accounts: hostusers.HostAccounts) -> Any:
    """Returns hook with the names in its user resolved to ids, or hook itself if there is nothing to
    resolve.
    """
    if not (isinstance(hook, dict) and hook.get("user")):
        return hook
    resolved = _resolve_spec(hook["user"], accounts)
    return hook if resolved == hook["user"] else {**hook, "user": resolved}


def _resolve_spec(spec: object, accounts: hostusers.HostAccounts) -> str:
    """Resolves a user spec: `name` becomes that account's `uid:gid`, a group name its gid.

    Numbers and unknown names stay. A uid alone stays alone: the policy refuses it rather than guess a group.
    """
    user, has_group, group = str(spec).partition(":")
    account = accounts.user(user) if user and ids.parse_id(user) is None else None
    uid = str(account[0]) if account else user
    if has_group:
        gid = _resolve_group(group, accounts)
    elif account:
        gid = str(account[1])  # a name brings its primary group, as with --as
    else:
        return str(spec) if uid == user else uid
    return f"{uid}:{gid}"


def _resolve_group(group: str, accounts: hostusers.HostAccounts) -> str:
    """Returns group as a gid if accounts knows its name; ids and unknown names are unchanged."""
    if ids.parse_id(group) is not None:
        return group
    gid = accounts.group(str(group))
    return group if gid is None else str(gid)


def _resolved_message(what: str, before: object, after: str) -> str:
    """Returns the notice that what was resolved from before to after on this host."""
    return f"{what} {json.dumps(before)} resolved to {json.dumps(after)} on this host"


NOT_REMOVABLE = "dockscreen always adds it, and cap_add is refused: a service that needs more cannot run"
DEFAULTS_HELP = ("a service that needs a capability or a setuid program fails, and cap_add is refused: "
                 "it cannot run under dockscreen")
RESOLVE_HELP = "write the ids (uid:gid) in the project to skip the lookup"


DEFAULTS = SubstitutionGroup(
    f'added cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] where missing, '
    "in services {services}", DEFAULTS_HELP)


def defaults_note() -> str:
    """Returns one general sentence about the defaults for generated files, instead of a line per service."""
    return (f'dockscreen also adds cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] to every '
            "service that lacks them, resolves user and group names to ids on this host, and runs a "
            "service that sets no user as the configured default user when its image would run as root, "
            "so these are not repeated here")
