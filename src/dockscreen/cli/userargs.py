"""This module provides functions for reading command lines that run something in a container (`docker compose
run` and `exec`, `docker exec`) just far enough to find the user and the service or container. `docker run`
is read by runargs, which uses the same GivenUsers.

The command line is trusted, so the user it gives is not checked against the id rules, only for its
form (Policy.check_user_options): numeric `uid:gid`, which docker uses as it stands. A name would be
resolved in the image (for `exec`, in the running container's /etc/passwd, which the container may have
rewritten), and a uid alone takes its group from the image. `--as NAME` names an account on this host
instead, and `--as-me` the caller's own ids. Reading changes nothing: the arguments keep both as their
UserOption, which the policy resolves (Policy.resolve_user_options), and which resolved replaces by
`--user=uid:gid` before compose or docker sees them.

A misreading cannot loosen anything: a user that is missed reaches compose as typed, which the command
line could have done with plain compose anyway, and a service that is missed has its image decided as
if no user had been chosen.
"""

import copy
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import NamedTuple, Self

from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime
from dockscreen.screen.notices import Notice
from dockscreen.screen.rules.commandline import Resolution, UserOption
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, messages

# Options of `docker compose run` and `exec` that take a value in the next argument.
COMPOSE_VALUE_FLAGS = {
    "run": frozenset({
        "--cap-add", "--cap-drop", "-e", "--env", "--env-from-file", "--entrypoint", "-l", "--label",
        "--name", "-p", "--publish", "--pull", "-u", "--user", "-v", "--volume", "-w", "--workdir",
    }),
    "exec": frozenset({"-e", "--env", "--index", "-u", "--user", "-w", "--workdir"}),
}


# An argument as read: a string, or the UserOption of --as or --as-me until it is resolved (resolved).
Arg = str | UserOption


class GivenUsers:
    """Collector of the users a command line gives, filled while the line is read, for the policy to judge and
    resolve. It holds each user option given, whether a user was chosen, the options that take a value, and
    once resolved, the notices of resolving them.

    The three are lists that only its own methods add to; callers must not change them.

    The parsers of this module and of runargs create and fill it; nothing changes it after they return,
    though nothing enforces that. A copy with --as and --as-me resolved comes from resolved.

    Attributes:
    - chosen: whether the command line chooses a user (--user, -u, --as or --as-me)
    - given: the user options given, as UserOption records
    - values: each option that takes a value, with it; --as and --as-me are under --user, as their UserOption
      until resolved
    - notices: what resolving --as did, for the caller to print; empty until resolved
    """

    def __init__(self, me: tuple[int, int], accounts: hostusers.HostAccounts) -> None:
        """Starts with no user given.

        Parameters:
        - me: the (uid, gid) that --as-me stands for
        - accounts: where the name given to --as is looked up
        """
        self.callers_ids = me
        self.accounts = accounts
        self.chosen = False
        self.notices: list[Notice] = []
        self.given: list[UserOption] = []
        self.values: list[tuple[str, Arg]] = []

    def value(self, option: str, value: Arg) -> None:
        """Records that option takes value."""
        self.values.append((option, value))

    def numeric(self, spec: str) -> None:
        """Records spec, the value of --user or -u, which docker gets as given."""
        self.chosen = True
        self.given.append(UserOption("--user", spec))

    def account(self, name: str) -> UserOption:
        """Returns the UserOption of --as with name, with the ids of the local account of that name if there
        is one, and records it.
        """
        return self._chosen(UserOption(commandline.AS, name, self.accounts.user(name) if name else None))

    def me(self) -> UserOption:
        """Returns the UserOption of --as-me, with the caller's own ids, and records it."""
        return self._chosen(UserOption(commandline.AS_ME, "", self.callers_ids))

    def resolved(self, resolutions: Mapping[UserOption, Resolution]) -> Self:
        """Returns a copy whose values have --as and --as-me replaced by the users they stand for (resolved),
        with the notices of the resolutions.
        """
        found = copy.copy(self)
        found.values = [(option, _resolved_arg(value, resolutions, bare=True))
                        for option, value in self.values]
        found.notices = [r.notice for r in resolutions.values() if r.notice]
        return found

    def _chosen(self, option: UserOption) -> UserOption:
        """Records option, of --as or --as-me, as the user chosen, and returns it."""
        self.chosen = True
        self.given.append(option)
        self.value("--user", option)
        return option


class UserArgs(NamedTuple):
    """Record of what a command line that runs something in a container says about the service or container
    it names and about the user, read only far enough to find those. It holds the service or container, the
    arguments, and the users it gives.

    It is for the commands that name a service or container: `docker compose run` keeps it, because the
    service it names is the one whose user the command line chooses, so the image does not decide it, and
    because its options are applied to that service (compose.runoptions). `docker compose up` and `create`
    keep one that names no service. `exec`, for compose and docker alike, only needs the rewritten arguments
    (resolve_user_args). `docker run` has a record of its own, runargs.RunArgs, which also holds the image
    and the options only `run` has; both keep the users in a GivenUsers, which resolves and collects them.

    Instances come from parse and parse_compose, or from unread for a subcommand that takes neither a service
    nor a user.

    Attributes:
    - service: the service or container it names, or None
    - args: the arguments, with --as and --as-me as their UserOption until resolved
    - users: what the command line says about the user before the service (GivenUsers)
    """
    service: str | None
    args: tuple[Arg, ...]
    users: GivenUsers

    def resolved(self, resolutions: Mapping[UserOption, Resolution]) -> Self:
        """Returns this record with --as and --as-me replaced by `--user=uid:gid` (the function resolved)."""
        return self._replace(args=resolved(self.args, resolutions), users=self.users.resolved(resolutions))

    @classmethod
    def unread(cls, args: list[str], runtime: Runtime) -> "UserArgs":
        """Returns args as a command line that names no service and gives no user, for a subcommand that
        takes neither (`up`, `create`).
        """
        return cls(None, tuple(args), GivenUsers(runtime.me, runtime.accounts))


def parse(args: Sequence[str], value_flags: Collection[str], me: tuple[int, int],
          accounts: hostusers.HostAccounts) -> UserArgs:
    """Parses args far enough to find the service or container, and whether a user is given.

    Returns a UserArgs, with --as and --as-me as their UserOption, and the users given.

    Parameters:
    - args: the subcommand's arguments
    - value_flags: the command's options that take a value in the next argument
    - me: the (uid, gid) that --as-me stands for
    - accounts: where the name given to --as is looked up (hostusers.HostAccounts)
    """
    users = GivenUsers(me, accounts)
    kept: list[Arg] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            return UserArgs(args[i + 1] if i + 1 < len(args) else None, (*kept, *args[i:]), users)
        if token == commandline.AS_ME:
            kept.append(users.me())
            i += 1
        elif token.startswith("--"):
            i = _parse_long(args, i, value_flags, users, kept)
        elif token.startswith("-") and token != "-":
            i = _parse_short(args, i, value_flags, users, kept)
        else:
            return UserArgs(token, (*kept, *args[i:]), users)
    return UserArgs(None, tuple(kept), users)



def parse_compose(subcommand: str, args: Sequence[str], me: tuple[int, int],
                  accounts: hostusers.HostAccounts) -> UserArgs:
    """Returns parse of the arguments of `docker compose run` or `exec`.

    Parameters:
    - subcommand: `run` or `exec`
    - args: the subcommand's arguments
    - me, accounts: as parse takes them
    """
    return parse(args, COMPOSE_VALUE_FLAGS[subcommand], me, accounts)


def resolved(args: Iterable[Arg], resolutions: Mapping[UserOption, Resolution]) -> tuple[str, ...]:
    """Returns args with --as and --as-me replaced by `--user=uid:gid`, with the user each stands for. Raises
    KeyError for one that resolutions lacks: it must not reach docker.
    """
    return tuple(_resolved_arg(arg, resolutions) for arg in args)


def _resolved_arg(arg: Arg, resolutions: Mapping[UserOption, Resolution], bare: bool = False) -> str:
    """Returns arg, or for a UserOption the user it stands for: `--user=uid:gid`, or with bare `uid:gid`."""
    if isinstance(arg, str):
        return arg
    user = resolutions[arg].user
    return user if bare else f"--user={user}"


def resolve_user_args(args: Sequence[str], value_flags: Collection[str], runtime: Runtime
                      ) -> list[str] | None:
    """Returns args with --as and --as-me replaced by ids (resolved), and prints the notices of resolving
    names.

    Returns None, and reports why, if the user cannot be used (Screener.check_given_users).

    Parameters:
    - args: the subcommand's arguments
    - value_flags: as parse takes them
    - runtime: the Runtime of the command, whose accounts and policy the users are resolved and judged with
    """
    parsed = parse(args, value_flags, runtime.me, runtime.accounts)
    screener = Screener(runtime)
    refused = screener.check_given_users(parsed.users.given)
    if not refused.passed:
        refused.show()
        return None
    parsed = parsed.resolved(screener.resolve_given_users(parsed.users.given))
    for notice in parsed.users.notices:
        messages.notice(notice)
    return list(parsed.args)


def _parse_long(args: Sequence[str], i: int, value_flags: Collection[str], users: GivenUsers,
                kept: list[Arg]) -> int:
    """Reads the --option at args[i] into kept, --as as its UserOption, and returns the index after it."""
    name, has_value, value = args[i].partition("=")
    end = i
    if (name in value_flags or name == commandline.AS) and not has_value:
        end = i + 1
        value = args[end] if end < len(args) else ""
    if name == commandline.AS:
        kept.append(users.account(value))
        return end + 1
    if name == "--user":
        users.numeric(value)
    if name in value_flags:
        users.value(name, value)
    kept += args[i:end + 1]
    return end + 1


def _parse_short(args: Sequence[str], i: int, value_flags: Collection[str], users: GivenUsers,
                 kept: list[Arg]) -> int:
    """Reads the cluster at args[i] (such as -it or -u0:0) into kept, and returns the index after it."""
    token = args[i]
    short_values = {flag[1] for flag in value_flags if len(flag) == 2}
    end = i
    for j, char in enumerate(token[1:], start=1):
        if char not in short_values:
            continue
        value = token[j + 1:]
        if not value:
            end = i + 1
            value = args[end] if end < len(args) else ""
        if char == "u":
            users.numeric(value)
        users.value(f"-{char}", value)
        break  # a flag that takes a value ends the cluster: the rest of it is the value
    kept += args[i:end + 1]
    return end + 1
