"""This module provides functions for working out the uid and gids a container would run as from the image's
passwd and group files, as docker does.

The image's own /etc/passwd and /etc/group decide the identity docker would use, and the image is
untrusted, so the id rules (rules.userrules) decide whether the image may have it. Whatever is accepted runs
pinned as numbers, so a difference between this reading and docker's can at worst refuse a good image.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.host import hostusers
from dockscreen.model.image import UserIdentity

# What Go's unicode.IsSpace trims; Python's str.strip() differs (it also strips \x1c to \x1f).
GO_SPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009" \
           "\u200a\u2028\u2029\u202f\u205f\u3000"
INT64_MAX = 2**63 - 1
INT64_MIN = -(2**63)


def _lines(text: str) -> list[str]:
    """Returns the non-empty lines of a passwd or group file as moby reads them: split on newlines only,
    each stripped of surrounding whitespace as Go defines it.
    """
    stripped = (line.strip(GO_SPACE) for line in text.split("\n"))
    return [line for line in stripped if line]


def _atoi(text: str) -> int:
    """Reads text as moby does with Go's strconv.Atoi: an optional sign and ASCII digits, else 0;
    a number out of the int64 range becomes the nearest limit.
    """
    digits = text[1:] if text[:1] in "+-" else text
    if not (digits and all(c in "0123456789" for c in digits)):
        return 0
    return max(INT64_MIN, min(INT64_MAX, int(text)))


def _fields(line: str, count: int) -> list[str]:
    """Returns the first count colon-separated fields of line, padding a short line with empty ones."""
    parts = line.split(":")[:count]
    return parts + [""] * (count - len(parts))


def _parse_passwd(text: str) -> list[tuple[str, int, int]]:
    """Parses a passwd file into [(name, uid, gid)] like moby: a missing or malformed number is 0."""
    entries = []
    for line in _lines(text):
        name, _, uid, gid, *_ = _fields(line, 7)
        entries.append((name, _atoi(uid), _atoi(gid)))
    return entries


def _parse_group(text: str) -> list[tuple[str, int, list[str]]]:
    """Parses a group file into [(name, gid, members)] like moby: a missing or malformed gid is 0."""
    entries = []
    for line in _lines(text):
        name, _, gid, members = _fields(line, 4)
        entries.append((name, _atoi(gid), members.split(",") if members else []))
    return entries


def resolve(spec: str | None, passwd_text: str, group_text: str) -> UserIdentity:
    """Resolves a `user[:group]` spec to the UserIdentity docker would run it as, using the image's files.

    A numeric user or group is an id, never a name (moby looks it up by number only). A numeric
    uid without a passwd entry gets gid 0. Raises ValueError for a name the image does not define,
    which docker would refuse to start too, and for a negative id.

    Parameters:
    - spec: the `user[:group]`; None or "" for the image's default, root
    - passwd_text, group_text: the image's passwd and group files
    """
    passwd = _parse_passwd(passwd_text)
    groups = _parse_group(group_text)
    user_part, _, group_part = (spec or "0").partition(":")
    user_part = user_part or "0"  # moby: no user means the default, uid 0

    entry = _find(passwd, user_part)
    if entry:
        username, uid, default_gid = entry
    elif _is_id(user_part):
        username, uid, default_gid = None, int(user_part), 0
    else:
        raise ValueError(f"user {user_part!r} is not defined in the image")

    gid = default_gid
    if group_part:
        group = _find(groups, group_part)
        if group:
            gid = group[1]
        elif _is_id(group_part):
            gid = int(group_part)
        else:
            raise ValueError(f"group {group_part!r} is not defined in the image")

    if min(uid, gid) < 0:
        raise ValueError("the image's user has a negative id")
    # moby finds supplementary groups by user name, so a uid without a passwd entry has none
    supplementary = tuple(sorted({g[1] for g in groups if username and username in g[2]}))
    return UserIdentity(uid, gid, supplementary)


def _find(entries: Sequence[tuple[Any, ...]], arg: str) -> tuple[Any, ...] | None:
    """Returns the first entry (name, id, ...) that arg names, by id if arg is a number, else by name;
    None if there is none.
    """
    if _is_id(arg):
        return next((e for e in entries if e[1] == int(arg)), None)
    return next((e for e in entries if e[0] == arg), None)


def _is_id(text: str) -> bool:
    """Tells whether Go's Atoi reads text as a number: an optional sign and ASCII digits."""
    digits = text[1:] if text[:1] in "+-" else text
    return bool(digits) and all(c in "0123456789" for c in digits)


def describe(identity: UserIdentity, local: hostusers.HostAccounts | None = None) -> str:
    """Describes the identity in words, and which local accounts the ids are.

    Parameters:
    - identity: the ids
    - local: this host's accounts (hostusers.HostAccounts); None to leave them out
    """
    def who(kind: str, value: int) -> str:
        if local is None:
            return str(value)
        name = local.user_name(value) if kind == "user" else local.group_name(value)
        return f"{value} (local {kind} {name})" if name else f"{value} (no local {kind})"

    text = f"uid {who('user', identity.uid)}, gid {who('group', identity.gid)}"
    if identity.supplementary:
        text += ", supplementary gids " + ", ".join(who("group", g) for g in identity.supplementary)
    return text
