"""The arguments of a command that runs in a container (`docker compose run` and `exec`, `docker exec`),
read just far enough to find the user and the service or container.

The command line is trusted, so the user it gives is not checked against the id rules, only for its
form: numeric `uid:gid`, which docker uses as it stands. A name would be resolved in the image (for
`exec`, in the running container's /etc/passwd, which the container may have rewritten), and a uid
alone takes its group from the image. `--as NAME` names an account on this host instead; it is
replaced by `--user=uid:gid` before compose or docker sees it. So is `--as-me`, for the caller's own ids.

A misreading cannot loosen anything: a user that is missed reaches compose as typed, which the command
line could have done with plain compose anyway, and a service that is missed has its image decided as
if no user had been chosen.
"""

from collections.abc import Collection, Sequence
from typing import NamedTuple

from dockscreen import commandline, messages
from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime


class Parsed(NamedTuple):
    service: str | None
    user_given: bool  # --user, -u or --as before the service
    args: list        # args with --as NAME replaced by --user=uid:gid
    notices: list     # what resolving user names on this host did, for the caller to print


def parse(args: Sequence[str], value_flags: Collection[str], me: tuple[int, int],
          accounts: hostusers.HostAccounts) -> Parsed:
    """Parses args far enough to find the service or container, and whether a user is given.

    Returns a Parsed, with --as and --as-me replaced by ids. Raises hostusers.UserError for a user that is
    not numeric `uid:gid`, or an --as that does not name a local user.
    value_flags: the command's options that take a value in the next argument.
    me: the (uid, gid) that --as-me stands for.
    accounts: where the name given to --as is looked up (hostusers.HostAccounts).
    """
    users = hostusers.UserOptions(me, accounts)
    kept: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            service = args[i + 1] if i + 1 < len(args) else None
            return Parsed(service, users.user_given, [*kept, *args[i:]], users.notices)
        if token == commandline.AS_ME:
            kept.append(users.me())
            i += 1
        elif token.startswith("--"):
            i = _parse_long(args, i, value_flags, users, kept)
        elif token.startswith("-") and token != "-":
            i = _parse_short(args, i, value_flags, users, kept)
        else:
            return Parsed(token, users.user_given, [*kept, *args[i:]], users.notices)
    return Parsed(None, users.user_given, kept, users.notices)



def resolved(args: Sequence[str], value_flags: Collection[str], runtime: Runtime) -> list[str] | None:
    """Returns args with --as and --as-me replaced by ids, and prints the notices of resolving names.

    Returns None, and reports why, if the user cannot be used. value_flags: as parse takes them.
    """
    try:
        parsed = parse(args, value_flags, runtime.me, runtime.accounts)
    except hostusers.UserError as e:
        messages.report([str(e)])
        return None
    for notice in parsed.notices:
        messages.notice(notice)
    return parsed.args

def _parse_long(args: Sequence[str], i: int, value_flags: Collection[str], users: hostusers.UserOptions,
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


def _parse_short(args: Sequence[str], i: int, value_flags: Collection[str], users: hostusers.UserOptions,
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
