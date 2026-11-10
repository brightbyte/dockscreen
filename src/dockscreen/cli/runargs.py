"""This module provides functions for reading a `docker run` command line just far enough to run it as `docker
create` + `docker start`.

We need the image position and the few flags that `run` has and `create` lacks
(`-d`, `--sig-proxy`, `--detach-keys`, `-a`). Nothing security-relevant hangs
on this: the policy looks at the container the daemon created from the result,
and docker_run checks that our reading of the command line matched the daemon's.

Reading changes nothing but what `create` lacks: --as and --as-me are kept as their UserOption, as userargs
keeps them, until they are resolved.
"""

from collections.abc import Mapping, Sequence
from typing import NamedTuple, Self

from dockscreen.cli import userargs
from dockscreen.cli.userargs import Arg
from dockscreen.host import hostusers
from dockscreen.screen.rules.userrules import Resolution, UserOption
from dockscreen.util import commandline

# Long options of `docker run`/`create` that take a value in the next argument.
LONG_VALUE_FLAGS = frozenset({
    "--add-host", "--annotation", "--attach", "--blkio-weight", "--blkio-weight-device", "--cap-add",
    "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota",
    "--cpu-rt-period", "--cpu-rt-runtime", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems",
    "--detach-keys", "--device", "--device-cgroup-rule", "--device-read-bps", "--device-read-iops",
    "--device-write-bps", "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname",
    "--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
    "--health-interval", "--health-retries", "--health-start-interval", "--health-start-period",
    "--health-timeout", "--hostname", "--ip", "--ip6", "--ipc", "--isolation", "--kernel-memory",
    "--label", "--label-file", "--link", "--link-local-ip", "--log-driver", "--log-opt", "--mac-address",
    "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
    "--network", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform", "--publish",
    "--pull", "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
    "--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "--user", "--userns", "--uts", "--volume",
    "--volume-driver", "--volumes-from", "--workdir",
})
SHORT_VALUE_FLAGS = frozenset("acehlmpuvw")
# Every option that takes the next argument as its value, ours included, as it is typed.
VALUE_OPTIONS = LONG_VALUE_FLAGS | {commandline.AS} | {f"-{c}" for c in SHORT_VALUE_FLAGS}
# Options of `docker exec` that take a value in the next argument, as userargs reads them.
EXEC_VALUE_FLAGS = frozenset({
    "--detach-keys", "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir",
})


class ParseError(Exception):
    """Exception raised when a `docker run` command line cannot be read, because it has no image or an option
    lacks its value.
    """


class RunArgs(NamedTuple):
    """Record of what a `docker run` command line asks for, read far enough to run it as `docker create` and
    `docker start`. It holds the arguments for `create`, the image and its command, the options only `run`
    has, and what the command line says about the user.

    It is the counterpart of userargs.UserArgs for `docker run`, which names an image where the others name a
    service or container, and has the options `create` lacks; the users it gives are kept in the same
    GivenUsers.

    Instances come from parse.

    Attributes:
    - create_args: the arguments for `docker create`, with --as and --as-me as their UserOption until
      resolved
    - image: the image, as the command line names it
    - command: what follows the image
    - detach: whether `-d` or `--detach` was given
    - detach_keys: the value of `--detach-keys`, or None
    - users: what the command line says about the user before the image (GivenUsers)
    """
    create_args: tuple[Arg, ...]
    image: str
    command: tuple[str, ...]
    detach: bool
    detach_keys: str | None
    users: userargs.GivenUsers

    def resolved(self, resolutions: Mapping[UserOption, Resolution]) -> Self:
        """Returns this record with --as and --as-me replaced by `--user=uid:gid` (userargs.resolved)."""
        return self._replace(create_args=userargs.resolved(self.create_args, resolutions))


class _State:
    """Private helper of parse that holds what it has read of a command line so far."""
    def __init__(self, users: userargs.GivenUsers) -> None:
        self.users = users
        self.kept: list[Arg] = []
        self.detach = False
        self.detach_keys: str | None = None


def parse(args: Sequence[str], me: tuple[int, int], accounts: hostusers.HostAccounts) -> RunArgs:
    """Splits `docker run` arguments into the `docker create` arguments, the image, its command and
    the options `create` lacks, with --as and --as-me as their UserOption.

    Raises ParseError if there is no image or an option lacks its value. The users given are in users, for
    the policy to judge and resolve.

    Parameters:
    - args: the arguments after `run`
    - me: the (uid, gid) that --as-me stands for
    - accounts: where the name given to --as is looked up (hostusers.HostAccounts)
    """
    users = userargs.GivenUsers(me, accounts)
    state = _State(users)
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            state.kept.append(token)
            i += 1
            break
        if token.startswith("--"):
            i = _parse_long(args, i, state)
        elif token.startswith("-") and token != "-":
            i = _parse_short(args, i, state)
        else:
            break
    if i >= len(args):
        raise ParseError("no image found in the command line")
    return RunArgs((*state.kept, *args[i:]), args[i], tuple(args[i + 1:]), state.detach,
                   state.detach_keys, users)


def _parse_long(args: Sequence[str], i: int, state: _State) -> int:
    """Reads the --option at args[i] into state and returns the index after it, and after its value."""
    token = args[i]
    name, has_value, value = token.partition("=")
    if name == commandline.AS_ME:
        state.kept.append(state.users.me())
    elif name == commandline.AS:
        if not has_value:
            i += 1
            value = _value_at(args, i, name)
        state.kept.append(state.users.account(value))
    elif name == "--detach":
        state.detach = value.lower() != "false" if has_value else True
    elif name == "--sig-proxy":
        pass
    elif name in ("--detach-keys", "--attach"):
        if not has_value:
            i += 1
            value = _value_at(args, i, name)
        if name == "--detach-keys":
            state.detach_keys = value
    else:
        state.kept.append(token)
        if name in LONG_VALUE_FLAGS and not has_value:
            i += 1
            value = _value_at(args, i, name)
            state.kept.append(value)
        if name == "--user":
            state.users.numeric(value)
    return i + 1


def _parse_short(args: Sequence[str], i: int, state: _State) -> int:
    """Reads the option cluster at args[i], such as -itv or -p80:80, into state and returns the index
    after it, and after its value.
    """
    token = args[i]
    keep = ""
    next_is_value = False
    consumed = 1
    for j in range(1, len(token)):
        char = token[j]
        if char == "d":
            state.detach = True
        elif char in SHORT_VALUE_FLAGS:
            rest = token[j + 1:]
            if char == "a":  # --attach has no `create` equivalent; dropped with its value
                if not rest:
                    _value_at(args, i + 1, token)
                    consumed = 2
                break
            if char == "u":
                state.users.numeric(rest or _value_at(args, i + 1, token))
            keep += char + rest
            next_is_value = not rest
            break
        else:
            keep += char
    if keep:
        state.kept.append("-" + keep)
    if next_is_value:
        state.kept.append(_value_at(args, i + 1, token))
        consumed = 2
    return i + consumed


def _value_at(args: Sequence[str], index: int, flag: str) -> str:
    """Returns args[index], the value of flag. Raises ParseError if args end before it."""
    if index >= len(args):
        raise ParseError(f"{flag} needs a value")
    return args[index]
