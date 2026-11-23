"""This module provides functions for working out the uid and gids a container would run as from the image's
passwd and group files, as docker does.

The image's own /etc/passwd and /etc/group decide the identity docker would use, and the image is untrusted,
so the id rules (rules.idrules) decide whether the image may have it. dockscreen runs an accepted identity
pinned as numbers, so a difference between this reading and docker's can at worst refuse a good image.

The function resolve reads the files as moby does, quirks included. An image can write them so that two
parsers read them in two ways:
- a uid field that is not a number (`app:x:1000x:...`) is 0 to moby, which is root; a strict parser would
  reject it or read it as 1000;
- whitespace that Python strips and Go does not (\x1c to \x1f) can make a line name a different user;
- the first of two entries for a name wins;
- moby looks up a numeric user by number only, so an entry whose name is "1000" cannot redirect `USER 1000`;
- moby finds supplementary groups by the user's name.

Reading the files the same way finds the root that docker would have used, so the decision is about the
identity that the image would really get.
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
    stripped_lines = (line.strip(GO_SPACE) for line in text.split("\n"))
    return [line for line in stripped_lines if line]


def _atoi(text: str) -> int:
    """Reads text as moby does with Go's strconv.Atoi. Text that is not an optional sign followed by ASCII
    digits gives 0. A number outside the int64 range becomes the nearest limit.
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
    uid without a passwd entry gets gid 0. Raises ValueError for a name that the image does not define
    (docker would refuse to start the container too), and for a negative id.

    Parameters:
    - spec: the `user[:group]`; None or "" for the image's default, root
    - passwd_text, group_text: the image's passwd and group files
    """
    passwd_entries = _parse_passwd(passwd_text)
    group_entries = _parse_group(group_text)
    user_part, _, group_part = (spec or "0").partition(":")
    user_part = user_part or "0"  # moby: no user means the default, uid 0

    entry = _find(passwd_entries, user_part)
    if entry:
        username, uid, default_gid = entry
    elif _is_id(user_part):
        username, uid, default_gid = None, int(user_part), 0
    else:
        raise ValueError(f"user {user_part!r} is not defined in the image")

    gid = default_gid
    if group_part:
        group_entry = _find(group_entries, group_part)
        if group_entry:
            gid = group_entry[1]
        elif _is_id(group_part):
            gid = int(group_part)
        else:
            raise ValueError(f"group {group_part!r} is not defined in the image")

    if min(uid, gid) < 0:
        raise ValueError("the image's user has a negative id")
    # moby finds supplementary groups by user name, so a uid without a passwd entry has none
    supplementary = tuple(sorted({g[1] for g in group_entries if username and username in g[2]}))
    return UserIdentity(uid, gid, supplementary)


def _find(entries: Sequence[tuple[Any, ...]], arg: str) -> tuple[Any, ...] | None:
    """Returns the first entry (name, id, ...) that arg names, by id if arg is a number, else by name;
    None if no entry matches.
    """
    if _is_id(arg):
        return next((e for e in entries if e[1] == int(arg)), None)
    return next((e for e in entries if e[0] == arg), None)


def _is_id(text: str) -> bool:
    """Tells whether Go's Atoi reads text as a number: an optional sign and ASCII digits."""
    digits = text[1:] if text[:1] in "+-" else text
    return bool(digits) and all(c in "0123456789" for c in digits)


def describe(identity: UserIdentity, local_accounts: hostusers.HostAccounts | None = None) -> str:
    """Describes the identity in words, and names the local accounts that the ids belong to.

    Parameters:
    - identity: the ids
    - local_accounts: this host's accounts (hostusers.HostAccounts); None to leave out the account names
    """
    def describe_id(kind: str, value: int) -> str:
        if local_accounts is None:
            return str(value)
        name = local_accounts.user_name(value) if kind == "user" else local_accounts.group_name(value)
        return f"{value} (local {kind} {name})" if name else f"{value} (no local {kind})"

    text = f"uid {describe_id('user', identity.uid)}, gid {describe_id('group', identity.gid)}"
    if identity.supplementary:
        text += ", supplementary gids " + ", ".join(describe_id("group", g) for g in identity.supplementary)
    return text
