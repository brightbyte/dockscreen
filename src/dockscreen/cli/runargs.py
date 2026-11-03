"""This module provides functions for reading a `docker run` command line just far enough to run it as `docker
create` + `docker start`.

We need the image position and the few flags that `run` has and `create` lacks
(`-d`, `--sig-proxy`, `--detach-keys`, `-a`). Nothing security-relevant hangs
on this: the policy looks at the container the daemon created from the result,
and docker_run checks that our reading of the command line matched the daemon's.
"""

from typing import NamedTuple

from dockscreen.cli import userargs
from dockscreen.host import hostusers
from dockscreen.screen.findings import Finding, Severity
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
# What `run` and `create` add before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
# Every option that takes the next argument as its value, ours included, as it is typed.
VALUE_OPTIONS = LONG_VALUE_FLAGS | {commandline.AS} | {f"-{c}" for c in SHORT_VALUE_FLAGS}
# Options of `docker exec` that take a value in the next argument, as userargs reads them.
EXEC_VALUE_FLAGS = frozenset({
    "--detach-keys", "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir",
})


class ParseError(Exception):
    pass


class ParsedRun(NamedTuple):
    """Reading of a `docker run` command line: the arguments for `docker create`, the image and command, what
    only `run` does with them, and what it says about the user (users).
    """
    create_args: list
    image: str
    command: list
    detach: bool
    detach_keys: str | None
    users: userargs.GivenUsers  # what it says about the user before the image


class _State:
    def __init__(self, users: userargs.GivenUsers) -> None:
        self.users = users
        self.kept: list[str] = []
        self.detach = False
        self.detach_keys: str | None = None


def parse(args: list[str], me: tuple[int, int], accounts: hostusers.HostAccounts) -> ParsedRun:
    """Splits `docker run` arguments into the `docker create` arguments, the image, its command and
    the options `create` lacks, with users given as ids.

    me: the (uid, gid) that --as-me stands for.
    accounts: where the name given to --as is looked up (hostusers.HostAccounts).
    Raises ParseError if there is no image or an option lacks its value. The users given are in users, for
    the policy to judge.
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
    return ParsedRun([*state.kept, *args[i:]], args[i], args[i + 1:], state.detach, state.detach_keys, users)


def _parse_long(args: list[str], i: int, state: _State) -> int:
    """Reads the --option at args[i] into state and returns the index after it, and after its value."""
    token = args[i]
    name, has_value, value = token.partition("=")
    if name == commandline.AS_ME:
        state.kept.append(state.users.me())
    elif name == commandline.ALLOW_ME:  # not a docker option: dropped
        state.users.allow_me = True
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
    elif name == "--user":
        if not has_value:
            i += 1
            value = _value_at(args, i, name)
        state.kept.append(state.users.numeric(value))
    else:
        state.kept.append(token)
        if name in LONG_VALUE_FLAGS and not has_value:
            i += 1
            state.kept.append(_value_at(args, i, name))
    return i + 1


def _parse_short(args: list[str], i: int, state: _State) -> int:
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
            if char == "u":  # a user is a value we may rewrite: move it out of the cluster
                value = rest or _value_at(args, i + 1, token)
                consumed = 1 if rest else 2
                if keep:
                    state.kept.append("-" + keep)
                state.kept.append(state.users.numeric(value))
                return i + consumed
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


def _value_at(args: list[str], index: int, flag: str) -> str:
    """Returns args[index], the value of flag. Raises ParseError if args end before it."""
    if index >= len(args):
        raise ParseError(f"{flag} needs a value")
    return args[index]


def defaults_notice() -> Finding:
    """Returns the routine finding that `run` and `create` add their defaults to every container."""
    return Finding(
        f"added {' '.join(DEFAULTS)}", Severity.ROUTINE,
        help="a program that needs a capability or setuid fails: add --cap-add or --security-opt yourself, "
             "which override these")
