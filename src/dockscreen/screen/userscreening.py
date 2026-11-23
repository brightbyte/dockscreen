"""This module provides functions for having the policy judge the users a command line gives (`--user`, `-u`,
`--as`, `--as-me`) and resolve `--as` and `--as-me` to ids, before the arguments reach docker or compose.

The modules userargs and runargs read the command lines, and keep `--as` and `--as-me` as their UserOption.
The rules judge and resolve them (Policy.check_user_options, Policy.resolve_user_options) through the Screener
of the command.

The user options need screening, though the command line is trusted, because the image decides their
meaning. Docker resolves a name in `--user` in the image's own /etc/passwd, or, for `exec`, in the running
container's /etc/passwd. The image or the container can make those files say root, and a uid alone gets its
group and supplementary groups from them. So `--user` must be numeric `uid:gid`, which means the same to
docker as to the policy. --as and --as-me are dockscreen's own: it resolves them on this host, and
replaces them by the `--user=uid:gid` they stand for before docker sees the arguments.
"""

from collections.abc import Collection, Mapping, Sequence
from typing import Protocol, TypeVar

from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.policy.rules.useroptionrules import Resolution, UserOption
from dockscreen.screen import userargs
from dockscreen.screen.screener import Screener
from dockscreen.screen.userargs import GivenUsers

# The record a command line as read resolves to.
Resolved_co = TypeVar("Resolved_co", covariant=True)
ArgsT = TypeVar("ArgsT")


class _ResolvableArgs(Protocol[Resolved_co]):
    """Protocol for a command line as read whose --as and --as-me can be resolved: userargs.UserArgs and
    runargs.RunArgs.
    """

    @property
    def users(self) -> GivenUsers: ...

    def with_users_resolved(self, resolutions: Mapping[UserOption, Resolution]) -> Resolved_co: ...


def screen_user_options(parsed_args: _ResolvableArgs[ArgsT], screener: Screener
                        ) -> tuple[Report, ArgsT | None]:
    """Has the policy judge the users that parsed_args gives, and resolve its --as and --as-me
    (Screener.check_given_users, Screener.resolve_given_users). Returns the report, and parsed_args with
    those options replaced by ids (userargs.resolve_user_options).

    If the policy refuses a user, the report holds the refusals and the record is None. If the users pass,
    the report holds the notices of resolving them.

    Parameters:
    - parsed_args: the command line as read (userargs.UserArgs, runargs.RunArgs)
    - screener: the Screener of the command
    """
    check_report = screener.check_given_users(parsed_args.users.options)
    if not check_report.has_passed:
        return check_report, None
    resolutions = screener.resolve_given_users(parsed_args.users.options)
    resolution_report = Report(tuple(r.notice for r in resolutions.values() if r.notice))
    return resolution_report, parsed_args.with_users_resolved(resolutions)


def resolve_user_args(args: Sequence[str], value_flags: Collection[str], runtime: Runtime
                      ) -> tuple[Report, list[str] | None]:
    """Returns the report on the users that args give, with the notices of resolving names, and args with
    --as and --as-me replaced by ids (screen_user_options). The arguments are None if the policy refuses the
    users.

    Parameters:
    - args: the subcommand's arguments
    - value_flags: as userargs.parse takes them
    - runtime: the Runtime of the command; its accounts resolve the users, and its policy judges them
    """
    parsed_args = userargs.parse(args, value_flags, runtime.me, runtime.accounts)
    report, resolved_args = screen_user_options(parsed_args, Screener(runtime))
    return report, None if resolved_args is None else list(resolved_args.args)
