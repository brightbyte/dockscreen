"""This module provides functions for reading command lines that run something in a container (`docker compose
run` and `exec`, `docker exec`) just far enough to find the user and the service or container. `docker run`
is read by runargs, which uses the same GivenUsers.

The command line is trusted, so the user it gives is not checked against the id rules, only for its
form (Policy.check_user_options): numeric `uid:gid`, which docker uses as it stands. A name would be
resolved in the image (for `exec`, in the running container's /etc/passwd, which the container may have
rewritten), and a uid alone takes its group from the image. `--as NAME` names an account on this host
instead; it is replaced by `--user=uid:gid` before compose or docker sees it. So is `--as-me`, for the
caller's own ids.

A misreading cannot loosen anything: a user that is missed reaches compose as typed, which the command
line could have done with plain compose anyway, and a service that is missed has its image decided as
if no user had been chosen.
"""

from collections.abc import Collection, Sequence
from typing import NamedTuple

from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.rules.commandline import UserOption
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, ids, messages

# Options of `docker compose run` and `exec` that take a value in the next argument.
COMPOSE_VALUE_FLAGS = {
    "run": frozenset({
        "--cap-add", "--cap-drop", "-e", "--env", "--env-from-file", "--entrypoint", "-l", "--label",
        "--name", "-p", "--publish", "--pull", "-u", "--user", "-v", "--volume", "-w", "--workdir",
    }),
    "exec": frozenset({"-e", "--env", "--index", "-u", "--user", "-w", "--workdir"}),
}


class GivenUsers:
    """Collector of the users a command line gives, filled while the line is read, for the policy to judge and
    the command to run with. It holds each user option given, whether a user was chosen, the notices that
    resolving names produced, and the options that take a value.

    The three are lists that only its own methods add to; callers must not change them.

    The parsers of this module and of runargs create and fill it, turning each user option into
    `--user=uid:gid` through its methods; nothing changes it after they return,
    though nothing enforces that.

    Attributes:
    - chosen: whether the command line chooses a user (--user, -u, --as or --as-me)
    - notices: what resolving user names on this host did, for the caller to print
    - given: the user options given, as UserOption records
    - values: each option that takes a value, with it, as docker gets it
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
        self.notices: list[str] = []
        self.given: list[UserOption] = []
        self.values: list[tuple[str, str]] = []

    def value(self, option: str, value: str) -> None:
        """Records that option takes value, as docker gets it."""
        self.values.append((option, value))

    def numeric(self, spec: str) -> str:
        """Returns `--user=` for spec, and records it.

        Parameters:
        - spec: the value of --user or -u
        """
        self.chosen = True
        self.given.append(UserOption("--user", spec))
        return f"--user={spec}"

    def account(self, name: str) -> str:
        """Returns `--user=` with the ids of the local account called name (--as), and keeps the notice;
        or returns --as as given if there is no such account. Records it either way.
        """
        self.chosen = True
        account = self.accounts.user(name) if name else None
        self.given.append(UserOption(commandline.AS, name, account))
        if account is None:
            return f"{commandline.AS}={name}"
        uid, gid = account
        self.notices.append(f"Resolving user {name} to uid {uid}, gid {gid}")
        self.value("--user", ids.format_user(account))
        return f"--user={ids.format_user(account)}"

    def me(self) -> str:
        """Returns `--user=` with the caller's own ids (--as-me), and records that a user was chosen."""
        self.chosen = True
        self.value("--user", ids.format_user(self.callers_ids))
        return f"--user={ids.format_user(self.callers_ids)}"


class UserArgs(NamedTuple):
    """Record of what a command line that runs something in a container says about the service or container
    it names and about the user, read only far enough to find those. It holds the service or container, the
    arguments with --as and --as-me replaced by ids, and the users it gives.

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
    - args: the arguments, with --as and --as-me replaced by `--user=uid:gid`
    - users: what the command line says about the user before the service (GivenUsers)
    """
    service: str | None
    args: tuple[str, ...]
    users: GivenUsers

    @classmethod
    def unread(cls, args: list[str], runtime: Runtime) -> "UserArgs":
        """Returns args as a command line that names no service and gives no user, for a subcommand that
        takes neither (`up`, `create`).
        """
        return cls(None, tuple(args), GivenUsers(runtime.me, runtime.accounts))


def parse(args: Sequence[str], value_flags: Collection[str], me: tuple[int, int],
          accounts: hostusers.HostAccounts) -> UserArgs:
    """Parses args far enough to find the service or container, and whether a user is given.

    Returns a UserArgs, with --as and --as-me replaced by ids, and the users given.

    Parameters:
    - args: the subcommand's arguments
    - value_flags: the command's options that take a value in the next argument
    - me: the (uid, gid) that --as-me stands for
    - accounts: where the name given to --as is looked up (hostusers.HostAccounts)
    """
    users = GivenUsers(me, accounts)
    kept: list[str] = []
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


def resolve_user_args(args: Sequence[str], value_flags: Collection[str], runtime: Runtime
                      ) -> list[str] | None:
    """Returns args with --as and --as-me replaced by ids, and prints the notices of resolving names.

    Returns None, and reports why, if the user cannot be used (Screener.check_given_users).

    Parameters:
    - args: the subcommand's arguments
    - value_flags: as parse takes them
    - runtime: the Runtime of the command, whose accounts and policy the users are resolved and judged with
    """
    parsed = parse(args, value_flags, runtime.me, runtime.accounts)
    if not verdict.screened(Screener(runtime).check_given_users(parsed.users.given)):
        return None
    for notice in parsed.users.notices:
        messages.notice(notice)
    return list(parsed.args)

def _parse_long(args: Sequence[str], i: int, value_flags: Collection[str], users: GivenUsers,
                kept: list[str]) -> int:
    """Reads the --option at args[i] into kept, with --as replaced, and returns the index after it."""
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
                 kept: list[str]) -> int:
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
