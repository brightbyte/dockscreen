"""Which uids and gids a project or an image may choose for a container.

Applies to every id that comes from an untrusted source: `user:` and hook users in a compose
file, and the user an image runs as. Ids from the command line and the config file are trusted and are
not checked here.

Never accepted, unless they are allowed ids (below):
- 0, root;
- an id that exists on this host: the container would share that account's kernel limits
  (processes, inotify watches), and own its files in anything it mounts;
- an id in a subordinate range (/etc/subuid, /etc/subgid, any owner): files with these ids belong to
  rootless containers on this host;
- 65535 and 4294967295, which tools read as "no id";
- an id above 2147483647, which docker refuses and older daemons wrap or clamp.

With host mounts (bind mounts, devices, volumes_from, secrets, configs) the id must be an allowed id,
because what the container can write on the host depends on it.

Allowed ids: the nobody range and the default user from the config file, ids the caller adds for one
check (a configured image user), and the caller's own ids when --allow-me was given.
"""

from typing import NamedTuple

from dockscreen import config as configuration
from dockscreen import hostusers

SUBUID_FILE = "/etc/subuid"
SUBGID_FILE = "/etc/subgid"
# Current docker refuses larger ids. Older daemons wrap or clamp them, which can give uid 0 or the
# caller's own uid, so they are refused here with or without host mounts.
MAX_ID = 2**31 - 1


class Subordinate:
    """The subordinate id ranges of this host, read once: `name:start:count` lines, malformed ones skipped."""

    def __init__(self):
        self._read(SUBUID_FILE, SUBGID_FILE)

    @classmethod
    def new_for_testing(cls, uid_file, gid_file):
        """Returns a Subordinate read from the given files instead of this host's."""
        subordinate = cls.__new__(cls)
        subordinate._read(uid_file, gid_file)
        return subordinate

    def _read(self, uid_file, gid_file):
        self.ranges = {"uid": _read_ranges(uid_file), "gid": _read_ranges(gid_file)}

    def contains(self, kind, value):
        """Tells whether value lies in one of this host's subordinate ranges of kind ("uid" or "gid")."""
        return any(start <= value < start + count for start, count in self.ranges[kind])


class Rules(NamedTuple):
    me: tuple                              # (uid, gid) of the caller
    allow_me: bool                         # --allow-me (or --as-me on docker run)
    nobody_range: tuple                    # inclusive (low, high)
    default_user: tuple                    # (uid, gid) that replaces root
    local: hostusers.HostAccounts          # the accounts on this host
    subordinate: Subordinate               # ranges in /etc/subuid and /etc/subgid

    def with_settings(self, settings):
        """Returns these rules with the nobody range and default user of settings (config.effective)."""
        return self._replace(nobody_range=settings.nobody_range, default_user=settings.default_user)

    def _allowed(self, kind, value, extra=()):
        """Tells whether value is an allowed id of kind ("uid" or "gid").

        Allowed are the nobody range, and the ids of the default user, of the pairs in extra, and of the
        caller if allow_me is set.
        """
        index = 0 if kind == "uid" else 1
        low, high = self.nobody_range
        pairs = [self.default_user, *extra, *([self.me] if self.allow_me else [])]
        return low <= value <= high or any(pair[index] == value for pair in pairs)

    def problem(self, kind, value, mounts, extra=()):
        """Returns why value may not be used as an id of kind, or None if it may.

        kind: "uid", "gid" or "supplementary gid". mounts: the container has host mounts, which leaves
        only allowed ids. extra: further allowed (uid, gid) pairs.
        """
        base = "uid" if kind == "uid" else "gid"
        # first: allowed ids such as nobody usually exist on this host too
        if self._allowed(base, value, extra):
            return None
        if value == 0:
            return f"{kind} 0 is root"
        if value in configuration.NO_ID:
            return f"{kind} {value} means \"no id\" to many tools"
        if value > MAX_ID:
            return f"{kind} {value} is above {MAX_ID}, the largest id docker accepts"
        # before the account lookup, which finds the caller too but cannot give the --allow-me hint
        if value == self.me[0 if base == "uid" else 1]:
            return f"{kind} {value} is yours; pass --allow-me to allow it"
        name = self.local.user_name(value) if base == "uid" else self.local.group_name(value)
        if name is not None:
            account = "user" if base == "uid" else "group"
            return f"{kind} {value} exists on this host (local {account} {name})"
        if self.subordinate.contains(base, value):
            return f"{kind} {value} is in a subordinate id range of this host (rootless containers)"
        if mounts:
            low, high = self.nobody_range
            return f"{kind} {value} is not in the nobody range {low}-{high}, and there are host mounts"
        return None

    def problems(self, uid, gid, supplementary=(), mounts=False, extra=()):
        """Returns the problems with running as uid, gid and the supplementary gids; empty if there are none.

        An id that is None is not checked. mounts and extra are as for problem().
        """
        checks = [("uid", uid), ("gid", gid), *(("supplementary gid", g) for g in supplementary)]
        found = [self.problem(kind, value, mounts, extra) for kind, value in checks if value is not None]
        return [p for p in found if p]


def _read_ranges(path):
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
