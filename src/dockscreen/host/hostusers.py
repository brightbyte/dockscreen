"""This module provides what dockscreen knows about the users and groups of this host: its accounts, and
the subordinate id ranges of rootless containers.
"""

import grp
import pwd
from typing import Self

SUBUID_FILE = "/etc/subuid"
SUBGID_FILE = "/etc/subgid"


class HostAccounts:
    """Directory of the users and groups on this host, looked up through NSS (so LDAP and sssd accounts
    count).
    """

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


class Subordinate:
    """Table of the subordinate id ranges of this host, read once from `name:start:count` lines, malformed
    ones skipped.
    """

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
