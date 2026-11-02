"""This module provides the reading of command lines that run something in a container (`docker compose run`
and `exec`, `docker exec`), just far enough to find the user and the service or container.

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
from dockscreen.screen.policy import UserOption
from dockscreen.screen.scope import Scope
from dockscreen.util import commandline, ids, messages


class UserOptions:
    """Collector of the users a command line gives, which turns each into `--user=uid:gid` for docker.

    Records whether a user was given, whether the caller's own ids are allowed (--as-me), the notices that
    resolving names produced, and the users given (given), for the policy to judge
    (Policy.check_user_options).
    """

    def __init__(self, me: tuple[int, int], accounts: hostusers.HostAccounts) -> None:
        """Starts with no user given; me: the (uid, gid) --as-me stands for; accounts: where --as looks."""
        self.callers_ids = me
        self.accounts = accounts
        self.user_given = False
        self.allow_me = False
        self.notices: list[str] = []
        self.given: list[UserOption] = []

    def numeric(self, spec: str) -> str:
        """Returns `--user=` for spec (--user or -u), and records it."""
        self.user_given = True
        self.given.append(UserOption("--user", spec))
        return f"--user={spec}"

    def account(self, name: str) -> str:
        """Returns `--user=` with the ids of the local account called name (--as), and keeps the notice;
        or returns --as as given if there is no such account. Records it either way.
        """
        self.user_given = True
        account = self.accounts.user(name) if name else None
        self.given.append(UserOption(commandline.AS, name, account))
        if account is None:
            return f"{commandline.AS}={name}"
        uid, gid = account
        self.notices.append(f"Resolving user {name} to uid {uid}, gid {gid}")
        return f"--user={ids.format_user(account)}"

    def me(self) -> str:
        """Returns `--user=` with the caller's own ids (--as-me), and records that those are allowed."""
        self.user_given = self.allow_me = True
        return f"--user={ids.format_user(self.callers_ids)}"


class Parsed(NamedTuple):
    """Reading of a command line that runs something in a container: the service or container it names,
    whether it chooses a user, and its arguments with --as and --as-me replaced by ids.
    """
    service: str | None
    user_given: bool  # --user, -u or --as before the service
    args: list        # args with --as NAME replaced by --user=uid:gid
    notices: list     # what resolving user names on this host did, for the caller to print
    users: tuple = ()     # the users it gives (policy.UserOption), for the policy to judge


def parse(args: Sequence[str], value_flags: Collection[str], me: tuple[int, int],
          accounts: hostusers.HostAccounts) -> Parsed:
    """Parses args far enough to find the service or container, and whether a user is given.

    Returns a Parsed, with --as and --as-me replaced by ids, and the users given.
    value_flags: the command's options that take a value in the next argument.
    me: the (uid, gid) that --as-me stands for.
    accounts: where the name given to --as is looked up (hostusers.HostAccounts).
    """
    users = UserOptions(me, accounts)
    kept: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            service = args[i + 1] if i + 1 < len(args) else None
            return Parsed(service, users.user_given, [*kept, *args[i:]], users.notices, tuple(users.given))
        if token == commandline.AS_ME:
            kept.append(users.me())
            i += 1
        elif token.startswith("--"):
            i = _parse_long(args, i, value_flags, users, kept)
        elif token.startswith("-") and token != "-":
            i = _parse_short(args, i, value_flags, users, kept)
        else:
            return Parsed(token, users.user_given, [*kept, *args[i:]], users.notices, tuple(users.given))
    return Parsed(None, users.user_given, kept, users.notices, tuple(users.given))



def resolved(args: Sequence[str], value_flags: Collection[str], runtime: Runtime) -> list[str] | None:
    """Returns args with --as and --as-me replaced by ids, and prints the notices of resolving names.

    Returns None, and reports why, if the user cannot be used (Policy.check_user_options). value_flags: as
    parse takes them.
    """
    parsed = parse(args, value_flags, runtime.me, runtime.accounts)
    refusals = Scope(runtime).policy_context(None).check_user_options(parsed.users)
    if refusals:
        messages.report(refusals)
        return None
    for notice in parsed.notices:
        messages.notice(notice)
    return parsed.args

def _parse_long(args: Sequence[str], i: int, value_flags: Collection[str], users: UserOptions,
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
    kept += args[i:end + 1]
    return end + 1


def _parse_short(args: Sequence[str], i: int, value_flags: Collection[str], users: UserOptions,
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
        break  # a flag that takes a value ends the cluster: the rest of it is the value
    kept += args[i:end + 1]
    return end + 1
