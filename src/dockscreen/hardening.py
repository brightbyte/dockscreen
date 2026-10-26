"""Defaults dockscreen adds to every service before running it.

A project does not have to set these itself: a service without `cap_drop: [ALL]`
or `no-new-privileges` gets them. Names in `user:`, hook users and `group_add` are resolved
to ids on this host, so the generated file never asks the image to resolve a name; the policy
then checks the ids, and refuses a name that does not exist here. A project cannot weaken them, because adding
`cap_add` or `no-new-privileges:false` is still refused by the policy. The
additions are reported by `audit` and written out by `harden`.
"""

import copy
import json
from typing import NamedTuple

from dockscreen import ids, messages, policy
from dockscreen.policy import CAP_DROP, SECURITY_OPT

class Addition(NamedTuple):
    service: str
    key: str
    message: str  # what was missing or a name, and what dockscreen does about it
    notable: bool = False  # the project set the key itself, so dockscreen changes what it chose
    help: str | None = None  # what the project can do about it


def apply(config, accounts):
    """(config with the defaults added and user names resolved, the list of additions).

    accounts: the users and groups to resolve names with (hostusers.HostAccounts).
    """
    hardened = copy.deepcopy(config)
    additions = []
    for name, service in (hardened.get("services") or {}).items():
        additions += resolve_user_names(name, service, accounts)
        if policy.check_cap_drop(service.get("cap_drop"), None):
            declared = service.get("cap_drop")
            reason = f"lacks {CAP_DROP}" if declared else "is not set"
            service["cap_drop"] = [*(declared or []), CAP_DROP]
            additions.append(Addition(
                name, "cap_drop", f"cap_drop {reason}; added {json.dumps([CAP_DROP])}",
                notable=bool(declared), help=NOT_REMOVABLE))
        if not policy.has_no_new_privileges(service.get("security_opt")):
            declared = service.get("security_opt")
            reason = "lacks no-new-privileges" if declared else "is not set"
            service["security_opt"] = [*(declared or []), SECURITY_OPT]
            additions.append(Addition(
                name, "security_opt",
                f"security_opt {reason}; added {json.dumps([SECURITY_OPT])}",
                notable=bool(declared), help=NOT_REMOVABLE))
    return hardened, additions


def resolve_user_names(name, service, accounts):
    """Replace names in the service's user, hook users and group_add by their ids on this host."""
    additions = []
    if service.get("user"):
        resolved = resolve_spec(service["user"], accounts)
        if resolved != service["user"]:
            additions.append(Addition(name, "user", resolved_message("user", service["user"], resolved),
                                      help=RESOLVE_HELP))
            service["user"] = resolved
    for key in ("post_start", "pre_stop"):
        for hook in service.get(key) or []:
            if isinstance(hook, dict) and hook.get("user"):
                resolved = resolve_spec(hook["user"], accounts)
                if resolved != hook["user"]:
                    message = resolved_message(f"{key} user", hook["user"], resolved)
                    additions.append(Addition(name, key, message, help=RESOLVE_HELP))
                    hook["user"] = resolved
    if service.get("group_add"):
        resolved = [resolve_group(g, accounts) for g in service["group_add"]]
        if resolved != service["group_add"]:
            additions.append(Addition(name, "group_add", resolved_message(
                "group_add", service["group_add"], resolved), help=RESOLVE_HELP))
            service["group_add"] = resolved
    return additions


def resolve_spec(spec, accounts):
    """`name` becomes that account's `uid:gid`, a group name its gid; numbers and unknown names stay.

    A uid alone stays alone: the policy refuses it rather than guess a group.
    """
    user, has_group, group = str(spec).partition(":")
    account = accounts.user(user) if user and ids.parse_id(user) is None else None
    uid = str(account[0]) if account else user
    if has_group:
        gid = resolve_group(group, accounts)
    elif account:
        gid = str(account[1])  # a name brings its primary group, as with --as
    else:
        return str(spec) if uid == user else uid
    return f"{uid}:{gid}"


def resolve_group(group, accounts):
    if ids.parse_id(group) is not None:
        return group
    gid = accounts.group(str(group))
    return group if gid is None else str(gid)


def resolved_message(what, before, after):
    return f"{what} {json.dumps(before)} resolved to {json.dumps(after)} on this host"


DEFAULT_KEYS = ("cap_drop", "security_opt")
NOT_REMOVABLE = "dockscreen always adds it, and cap_add is refused: a service that needs more cannot run"
DEFAULTS_HELP = ("a service that needs a capability or a setuid program fails, and cap_add is refused: "
                 "it cannot run under dockscreen")
RESOLVE_HELP = "write the ids (uid:gid) in the project to skip the lookup"


def describe(additions):
    """Marked lines for an audit or a run: what dockscreen changed, and how much it deserves a look.

    A default added where the project set nothing is routine, and one line names the services, since it
    is the same for all. A key the project set itself, and a name resolved on this host, get a line each.
    """
    lines = []
    for a in additions:
        if a.key in DEFAULT_KEYS and not a.notable:
            continue
        make = messages.notable_change if a.notable else messages.routine_change
        lines.append(make(f"service {a.service}: {a.message}", a.help))
    services = list(dict.fromkeys(a.service for a in additions if a.key in DEFAULT_KEYS and not a.notable))
    if services:
        lines.append(messages.routine_change(
            f'added cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] where missing, '
            f"in services {', '.join(services)}", DEFAULTS_HELP))
    return lines


def defaults_note():
    """One general sentence for generated files, instead of a line per service."""
    return (f'dockscreen also adds cap_drop: ["{CAP_DROP}"] and security_opt: ["{SECURITY_OPT}"] to every '
            "service that lacks them, resolves user and group names to ids on this host, and runs a "
            "service that sets no user as the configured default user when its image would run as root, "
            "so these are not repeated here")
