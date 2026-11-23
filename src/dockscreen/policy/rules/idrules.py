"""This module defines the IdRules class, the group of the policy's rules for the uids and gids that
containers run as, and the record of the facts these rules judge ids by (IdFacts).

The rules check every id that comes from an untrusted source: `user:` and hook users in a compose file, and
the user an image runs as. Ids from the command line and the config file are trusted, and these rules do
not check them. The rules never accept these, unless they are allowed ids (below):
- 0, root;
- an id that exists on this host: the container would share that account's kernel limits (processes,
  inotify watches), and it would own that account's files in anything it mounts;
- an id in a subordinate range (/etc/subuid, /etc/subgid, any owner): files with these ids belong to
  rootless containers on this host;
- 65535 and 4294967295, which tools read as "no id";
- an id above 2147483647, which docker refuses and older daemons wrap or clamp.

With host mounts (bind mounts, devices, volumes_from, secrets, configs), the id must be an allowed id,
because the id decides which host files the container can write.

The invoking user's own ids are ids on this host too, and they are the most useful ones to a project. A
container that runs as the invoking user can write all of their files that it mounts, such as the
project's .git/hooks; the user later runs those scripts outside any container. A project gets these ids
only with --allow-me, and only for that run.

Allowed ids are:
- the nobody range and the default user, from the config file;
- the ids that the calling code adds for one check (a configured image user);
- the invoking user's own ids, when they gave --allow-me (compose only).
"""

from collections.abc import Collection, Iterable
from typing import NamedTuple

from dockscreen.host import hostusers
from dockscreen.policy.rules.base import RuleBase
from dockscreen.util import commandline, ids

# Current docker refuses larger ids. Older daemons wrap or clamp them, which can give uid 0 or the
# invoking user's own uid, so the rules refuse them here with or without host mounts.
MAX_ID = 2**31 - 1

# The hint that comes with a refusal of an id of the invoking user's, by command: the way to allow it there.
COMPOSE_HINT = f"pass {commandline.ALLOW_ME_OPTION} to allow it"
RUN_HINT = f"pass {commandline.AS_ME_OPTION} to run as you"


class IdFacts(NamedTuple):
    """Value object for the facts that the id rules (IdRules.id_problems) judge uids and gids by, besides
    the settings of the config file, which the policy holds. The facts are the invoking user's ids and whether
    they are allowed, this host's accounts and subordinate ranges, and the command's hint for allowing the
    invoking user's ids.

    Instances come from Screener.ids, which takes them from the Runtime of the command.

    Attributes:
    - me: the invoking user's (uid, gid)
    - is_me_allowed: whether the invoking user's ids are allowed (--allow-me)
    - local_accounts: the accounts on this host (HostAccounts)
    - subordinate: the ranges in /etc/subuid and /etc/subgid (SubordinateRanges)
    - own_ids_hint: the command's way to allow the invoking user's ids, given after refusing them; empty if
      the command has no way
    """
    me: tuple
    is_me_allowed: bool
    local_accounts: hostusers.HostAccounts
    subordinate: hostusers.SubordinateRanges
    own_ids_hint: str = COMPOSE_HINT


class IdRules(RuleBase):
    """Mixin of Policy with the rules for the uids and gids that containers run as. It is not used on its
    own. UserRules applies these rules to the users of services and images.
    """

    def _is_allowed_id(self, kind: str, value: int, allowed_pairs: Iterable[tuple[int, int]] = ()) -> bool:
        """Tells whether value is an allowed id of kind ("uid" or "gid").

        Allowed are the nobody range, and the ids of the default user, of the pairs in allowed_pairs, and of
        the invoking user if is_me_allowed is set.
        """
        index = 0 if kind == "uid" else 1
        low, high = self.nobody_range
        pairs = [self.default_user, *allowed_pairs, *([self.ids.me] if self.ids.is_me_allowed else [])]
        return low <= value <= high or any(pair[index] == value for pair in pairs)

    def id_problem(self, kind: str, value: int, has_mounts: bool,
                   allowed_pairs: Iterable[tuple[int, int]] = ()) -> str | None:
        """Returns the reason that value may not be used as an id of kind, or None if it may.

        Parameters:
        - kind: "uid", "gid" or "supplementary gid"
        - value: the id
        - has_mounts: the container has host mounts, which leaves only allowed ids
        - allowed_pairs: further allowed (uid, gid) pairs
        """
        base = "uid" if kind == "uid" else "gid"
        # first: allowed ids such as the nobody user's usually exist on this host too
        if self._is_allowed_id(base, value, allowed_pairs):
            return None
        if value == 0:
            return f"{kind} 0 is root"
        if value in ids.NO_ID:
            return f"{kind} {value} means \"no id\" to many tools"
        if value > MAX_ID:
            return f"{kind} {value} is above {MAX_ID}, the largest id docker accepts"
        # before the account lookup, which finds the invoking user too, but cannot give the --allow-me hint
        if value == self.ids.me[0 if base == "uid" else 1]:
            hint = self.ids.own_ids_hint
            return f"{kind} {value} is yours" + (f"; {hint}" if hint else "")
        accounts = self.ids.local_accounts
        name = accounts.user_name(value) if base == "uid" else accounts.group_name(value)
        if name is not None:
            account = "user" if base == "uid" else "group"
            return f"{kind} {value} exists on this host (local {account} {name})"
        if self.ids.subordinate.contains(base, value):
            return f"{kind} {value} is in a subordinate id range of this host (rootless containers)"
        if has_mounts:
            low, high = self.nobody_range
            return f"{kind} {value} is not in the nobody range {low}-{high}, and there are host mounts"
        return None

    def id_problems(self, uid: int | None, gid: int | None, supplementary: Iterable[int] = (),
                    has_mounts: bool = False, allowed_pairs: Collection[tuple[int, int]] = ()) -> list[str]:
        """Returns the problems with running as uid, gid and the supplementary gids; empty if there are none.

        Parameters:
        - uid, gid: the ids; None for an id that is not checked
        - supplementary: the supplementary gids
        - has_mounts, allowed_pairs: as id_problem takes them
        """
        checks = [("uid", uid), ("gid", gid), *(("supplementary gid", g) for g in supplementary)]
        problems = [self.id_problem(kind, value, has_mounts, allowed_pairs) for kind,
                    value in checks if value is not None]
        return [p for p in problems if p]
