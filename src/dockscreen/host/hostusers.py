"""The accounts and subordinate id ranges of this host, and users given on the command line: ids as
typed, or a local account.

Docker resolves a user name in the container's own /etc/passwd, where an image can map it
to root. So `--user` takes only numbers, which mean the same everywhere, and `--as NAME` takes the
name of an account on this host and turns it into ids before docker sees it.
"""

import grp
import pwd
from typing import Self

from dockscreen import ids

SUBUID_FILE = "/etc/subuid"
SUBGID_FILE = "/etc/subgid"


class HostAccounts:
    """Users and groups on this host, through NSS (so LDAP and sssd accounts count)."""

    def user(self, name: str) -> tuple[int, int] | None:
        """Returns (uid, primary gid) of the user called name, or None if there is none."""
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            return None
        return account.pw_uid, account.pw_gid

    def group(self, name: str) -> int | None:
        """Returns the gid of the group called name, or None if there is none."""
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            return None

    def user_name(self, uid: int) -> str | None:
        """Returns the name of the user with this uid, or None if there is none."""
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return None

    def group_name(self, gid: int) -> str | None:
        """Returns the name of the group with this gid, or None if there is none."""
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None


class UserError(Exception):
    """A user given on the command line cannot be used."""


class UnknownUser(UserError):
    pass


DOCKER_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"


def _require_numeric(spec: str, alternatives: str = DOCKER_ALTERNATIVES) -> str:
    """Returns spec as typed if it is numeric `uid:gid`; raises UserError saying what to use otherwise.

    A uid alone would leave the group to the image: docker takes it, and the supplementary groups,
    from the image's own passwd and group files, which can say root.
    """
    if ids.parse_user(spec):
        return spec
    hint = "; give the group too, as uid:gid" if ids.is_id(spec) else ""
    raise UserError(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}{alternatives}")


def _resolve_account(name: str, accounts: HostAccounts) -> tuple[str, list[str]]:
    """Resolves name to the account of that name on this host; returns (`uid:gid`, notices).

    The gid is the account's primary group. accounts: where to look the name up (HostAccounts).
    Raises UserError for an empty name, an id or a `:`, UnknownUser if there is no such account.
    """
    if not name or ":" in name or ids.is_id(name):
        raise UserError(f"--as takes the name of a local user, not {name!r}; use --user for ids")
    account = accounts.user(name)
    if account is None:
        raise UnknownUser(f"user {name!r} does not exist on this host; use --user with a numeric id")
    uid, gid = account
    return ids.format_user(account), [f"Resolving user {name} to uid {uid}, gid {gid}"]


class UserOptions:
    """The ways a command line gives a user, each turned into `--user=uid:gid` for docker.

    Records whether a user was given, whether the caller's own ids are allowed (--as-me), and the
    notices that resolving names produced.
    """

    def __init__(self, me: tuple[int, int], accounts: HostAccounts) -> None:
        """Starts with no user given; me: the (uid, gid) --as-me stands for; accounts: where --as looks."""
        self.callers_ids = me
        self.accounts = accounts
        self.user_given = False
        self.allow_me = False
        self.notices: list[str] = []

    def numeric(self, spec: str) -> str:
        """Returns `--user=` for spec (--user or -u); raises UserError unless it is numeric `uid:gid`."""
        self.user_given = True
        return f"--user={_require_numeric(spec)}"

    def account(self, name: str) -> str:
        """Returns `--user=` with the ids of the local account called name (--as), and keeps the notice.

        Raises UserError if there is no such account (_resolve_account).
        """
        self.user_given = True
        resolved, messages = _resolve_account(name, self.accounts)
        self.notices += messages
        return f"--user={resolved}"

    def me(self) -> str:
        """Returns `--user=` with the caller's own ids (--as-me), and records that those are allowed."""
        self.user_given = self.allow_me = True
        return f"--user={ids.format_user(self.callers_ids)}"


class Subordinate:
    """The subordinate id ranges of this host, read once: `name:start:count` lines, malformed ones skipped."""

    def __init__(self) -> None:
        self._read(SUBUID_FILE, SUBGID_FILE)

    @classmethod
    def new_for_testing(cls, uid_file: str, gid_file: str) -> Self:
        """Returns a Subordinate read from the given files instead of this host's."""
        subordinate = cls.__new__(cls)
        subordinate._read(uid_file, gid_file)
        return subordinate

    def _read(self, uid_file: str, gid_file: str) -> None:
        self.ranges = {"uid": _read_ranges(uid_file), "gid": _read_ranges(gid_file)}

    def contains(self, kind: str, value: int) -> bool:
        """Tells whether value lies in one of this host's subordinate ranges of kind ("uid" or "gid")."""
        return any(start <= value < start + count for start, count in self.ranges[kind])


def _read_ranges(path: str) -> list[tuple[int, int]]:
    """Reads the (start, count) ranges of a subuid or subgid file; none if it cannot be read."""
    try:
        with open(path) as f:
            text = f.read()
    except OSError:
        return []
    ranges = []
    for line in text.splitlines():
        fields = line.strip().split(":")
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit():
            ranges.append((int(fields[1]), int(fields[2])))
    return ranges
