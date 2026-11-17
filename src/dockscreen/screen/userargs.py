"""This module provides functions for reading command lines that run something in a container (`docker compose
run` and `exec`, `docker exec`) just far enough to find the user and the service or container. runargs
reads `docker run`, with the same GivenUsers.

The command line is trusted, so the policy does not check the user it gives against the id rules, only its
form (Policy.check_user_options): numeric `uid:gid`, which docker uses as it stands. Docker would resolve a
name in the image (for `exec`, in the running container's /etc/passwd, which the container may have
rewritten), and a uid alone takes its group from the image. `--as NAME` names an account on this host
instead, and `--as-me` the invoking user's own ids. Reading changes nothing: the arguments keep both as their
UserOption, which the policy resolves (Policy.resolve_user_options), and which resolved replaces by
`--user=uid:gid` before compose or docker sees them.

A misreading cannot loosen anything: a user this misses reaches compose as typed, which the command line
could have done with plain compose anyway, and for a service this misses, the policy decides its image as
if the command line chose no user.
"""

from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Generic, NamedTuple, TypeVar

from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime
from dockscreen.policy.rules.userrules import Resolution, UserOption
from dockscreen.util import commandline

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

# The arguments a record holds: Arg as read, str once resolved.
ArgT = TypeVar("ArgT", bound=Arg)


class GivenUsers:
    """Collector of the users a command line gives, filled while the line is read, for the policy to judge and
    resolve (userscreening.screen_user_options). It holds each user option given, and whether a user was
    chosen.

    Only its own methods add to the list; callers must not change it.

    The parsers of this module and of runargs create and fill it; nothing changes it after they return,
    though nothing enforces that.

    Attributes:
    - is_user_chosen: whether the command line chooses a user (--user, -u, --as or --as-me)
    - options: the user options given, as UserOption records
    """

    def __init__(self, me: tuple[int, int], accounts: hostusers.HostAccounts) -> None:
        """Starts with no user given.

        Parameters:
        - me: the (uid, gid) that --as-me stands for
        - accounts: where the name given to --as is looked up
        """
        self.callers_ids = me
        self.accounts = accounts
        self.is_user_chosen = False
        self.options: list[UserOption] = []

    def record_numeric(self, spec: str) -> None:
        """Records spec, the value of --user or -u, which docker gets as given."""
        self.is_user_chosen = True
        self.options.append(UserOption("--user", spec))

    def record_account(self, name: str) -> UserOption:
        """Returns the UserOption of --as with name, with the ids of the local account of that name if there
        is one, and records it.
        """
        return self._record_choice(UserOption(commandline.AS_OPTION, name,
                                              self.accounts.user_ids(name) if name else None))

    def record_me(self) -> UserOption:
        """Returns the UserOption of --as-me, with the invoking user's own ids, and records it."""
        return self._record_choice(UserOption(commandline.AS_ME_OPTION, "", self.callers_ids))

    def _record_choice(self, option: UserOption) -> UserOption:
        """Records option, of --as or --as-me, as the user chosen, and returns it."""
        self.is_user_chosen = True
        self.options.append(option)
        return option


class UserArgs(NamedTuple, Generic[ArgT]):
    """Record of what a command line that runs something in a container says about the service or container
    it names and about the user, read only far enough to find those. It holds the service or container, the
    arguments, the users it gives, and the options that take a value.

    It is for the commands that name a service or container: `docker compose run` keeps it, because the
    service it names is the one whose user the command line chooses, so the image does not decide it, and
    because its options are applied to that service (screen.runoptions). `docker compose up` and `create`
    keep one that names no service. `exec`, for compose and docker alike, only needs the rewritten arguments
    (userscreening.resolve_user_args). `docker run` has a record of its own, runargs.RunArgs, which also
    holds the image and the options only `run` has; both keep the users in a GivenUsers.

    Instances come from parse and parse_compose, or from from_args for a subcommand that takes neither a
    service nor a user.

    Attributes:
    - service: the service or container it names, or None
    - args: the arguments, with --as and --as-me as their UserOption until resolved
    - users: what the command line says about the user before the service (GivenUsers)
    - values: each option before the service that takes a value, with it; --as and --as-me are under --user,
      as their UserOption until resolved
    """
    service: str | None
    args: tuple[ArgT, ...]
    users: GivenUsers
    values: tuple[tuple[str, ArgT], ...] = ()

    def with_users_resolved(self, resolutions: Mapping[UserOption, Resolution]) -> "UserArgs[str]":
        """Returns this record with --as and --as-me replaced by the users they stand for: `--user=uid:gid`
        in args (the function resolved), `uid:gid` in values.
        """
        values = tuple((option, _resolve_arg(value, resolutions, should_omit_option=True))
                       for option, value in self.values)
        return UserArgs(self.service, resolve_user_options(self.args, resolutions), self.users, values)

    @classmethod
    def from_args(cls, args: list[str], runtime: Runtime) -> "UserArgs[str]":
        """Returns args as a command line that names no service and gives no user, for a subcommand that
        takes neither (`up`, `create`).
        """
        return UserArgs(None, tuple(args), GivenUsers(runtime.me, runtime.accounts))


def parse(args: Sequence[str], value_flags: Collection[str], me: tuple[int, int],
          accounts: hostusers.HostAccounts) -> UserArgs[Arg]:
    """Parses args far enough to find the service or container, and whether a user is given.

    Returns a UserArgs, with --as and --as-me as their UserOption, and the users given.

    Parameters:
    - args: the subcommand's arguments
    - value_flags: the command's options that take a value in the next argument
    - me: the (uid, gid) that --as-me stands for
    - accounts: where the name given to --as is looked up (hostusers.HostAccounts)
    """
    reading = _Reading(GivenUsers(me, accounts))
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            return reading.result(args[i + 1] if i + 1 < len(args) else None, args[i:])
        if token == commandline.AS_ME_OPTION:
            reading.keep_choice(reading.users.record_me())
            i += 1
        elif token.startswith("--"):
            i = _parse_long(args, i, value_flags, reading)
        elif token.startswith("-") and token != "-":
            i = _parse_short(args, i, value_flags, reading)
        else:
            return reading.result(token, args[i:])
    return reading.result(None, ())


class _Reading:
    """Private helper of parse that holds what it has read of a command line so far."""

    def __init__(self, users: GivenUsers) -> None:
        self.users = users
        self.kept_args: list[Arg] = []
        self.values: list[tuple[str, Arg]] = []

    def keep_choice(self, option: UserOption) -> None:
        """Keeps option, of --as or --as-me, in the arguments, and as the value of --user."""
        self.kept_args.append(option)
        self.values.append(("--user", option))

    def result(self, service: str | None, remaining_args: Sequence[str]) -> UserArgs[Arg]:
        """Returns what was read, with service and the rest of the arguments after it."""
        return UserArgs(service, (*self.kept_args, *remaining_args), self.users, tuple(self.values))



def parse_compose(subcommand: str, args: Sequence[str], me: tuple[int, int],
                  accounts: hostusers.HostAccounts) -> UserArgs[Arg]:
    """Returns parse of the arguments of `docker compose run` or `exec`.

    Parameters:
    - subcommand: `run` or `exec`
    - args: the subcommand's arguments
    - me, accounts: as parse takes them
    """
    return parse(args, COMPOSE_VALUE_FLAGS[subcommand], me, accounts)


def resolve_user_options(args: Iterable[Arg], resolutions: Mapping[UserOption, Resolution]
                         ) -> tuple[str, ...]:
    """Returns args with --as and --as-me replaced by `--user=uid:gid`, with the user each stands for. Raises
    KeyError for one that resolutions lacks: it must not reach docker.
    """
    return tuple(_resolve_arg(arg, resolutions) for arg in args)


def _resolve_arg(arg: Arg, resolutions: Mapping[UserOption, Resolution],
                 should_omit_option: bool = False) -> str:
    """Returns arg, or for a UserOption the user it stands for: `--user=uid:gid`, or with should_omit_option
    `uid:gid`.
    """
    if isinstance(arg, str):
        return arg
    user = resolutions[arg].user
    return user if should_omit_option else f"--user={user}"


def _parse_long(args: Sequence[str], i: int, value_flags: Collection[str], reading: _Reading) -> int:
    """Reads the --option at args[i] into reading, --as as its UserOption, and returns the index after it."""
    name, equals_sign, value = args[i].partition("=")
    end = i
    if (name in value_flags or name == commandline.AS_OPTION) and not equals_sign:
        end = i + 1
        value = args[end] if end < len(args) else ""
    if name == commandline.AS_OPTION:
        reading.keep_choice(reading.users.record_account(value))
        return end + 1
    if name == "--user":
        reading.users.record_numeric(value)
    if name in value_flags:
        reading.values.append((name, value))
    reading.kept_args += args[i:end + 1]
    return end + 1


def _parse_short(args: Sequence[str], i: int, value_flags: Collection[str], reading: _Reading) -> int:
    """Reads the cluster at args[i] (such as -it or -u0:0) into reading, and returns the index after it."""
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
            reading.users.record_numeric(value)
        reading.values.append((f"-{char}", value))
        break  # a flag that takes a value ends the cluster: the rest of it is the value
    reading.kept_args += args[i:end + 1]
    return end + 1
