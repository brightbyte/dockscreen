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

from collections.abc import Collection, Iterable
from typing import NamedTuple, Self

from dockscreen import config as configuration
from dockscreen import hostusers
from dockscreen.runtime import Runtime

# Current docker refuses larger ids. Older daemons wrap or clamp them, which can give uid 0 or the
# caller's own uid, so they are refused here with or without host mounts.
MAX_ID = 2**31 - 1


class Rules(NamedTuple):
    me: tuple                              # (uid, gid) of the caller
    allow_me: bool                         # --allow-me (or --as-me on docker run)
    nobody_range: tuple                    # inclusive (low, high)
    default_user: tuple                    # (uid, gid) that replaces root
    local: hostusers.HostAccounts          # the accounts on this host
    subordinate: hostusers.Subordinate     # ranges in /etc/subuid and /etc/subgid

    @classmethod
    def for_runtime(cls, runtime: Runtime, allow_me: bool = False) -> Self:
        """Returns the id rules for the config file's settings; allow_me: the caller's own ids are allowed."""
        return cls(runtime.me, allow_me, runtime.settings.nobody_range, runtime.settings.default_user,
                   runtime.accounts, runtime.subordinate)

    def with_settings(self, settings: configuration.Config) -> Self:
        """Returns these rules with the nobody range and default user of settings (config.effective)."""
        return self._replace(nobody_range=settings.nobody_range, default_user=settings.default_user)

    def _allowed(self, kind: str, value: int, extra: Iterable[tuple[int, int]] = ()) -> bool:
        """Tells whether value is an allowed id of kind ("uid" or "gid").

        Allowed are the nobody range, and the ids of the default user, of the pairs in extra, and of the
        caller if allow_me is set.
        """
        index = 0 if kind == "uid" else 1
        low, high = self.nobody_range
        pairs = [self.default_user, *extra, *([self.me] if self.allow_me else [])]
        return low <= value <= high or any(pair[index] == value for pair in pairs)

    def problem(self, kind: str, value: int, mounts: bool,
                extra: Iterable[tuple[int, int]] = ()) -> str | None:
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

    def problems(self, uid: int | None, gid: int | None, supplementary: Iterable[int] = (),
                 mounts: bool = False, extra: Collection[tuple[int, int]] = ()) -> list[str]:
        """Returns the problems with running as uid, gid and the supplementary gids; empty if there are none.

        An id that is None is not checked. mounts and extra are as for problem().
        """
        checks = [("uid", uid), ("gid", gid), *(("supplementary gid", g) for g in supplementary)]
        found = [self.problem(kind, value, mounts, extra) for kind, value in checks if value is not None]
        return [p for p in found if p]
