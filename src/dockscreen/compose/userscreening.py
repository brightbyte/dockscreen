"""This module provides functions for having the policy judge the users a command line gives (`--user`, `-u`,
`--as`, `--as-me`) and resolve `--as` and `--as-me` to ids, before the arguments reach docker or compose.

The command lines are read by userargs and runargs, which keep `--as` and `--as-me` as their UserOption; the
rules judge and resolve them (Policy.check_user_options, Policy.resolve_user_options) through the Screener of
the command.
"""

from collections.abc import Collection, Mapping, Sequence
from typing import Protocol, TypeVar

from dockscreen.compose import userargs
from dockscreen.compose.screener import Screener
from dockscreen.compose.userargs import GivenUsers
from dockscreen.host.runtime import Runtime
from dockscreen.screen.report import Report
from dockscreen.screen.rules.userrules import Resolution, UserOption
from dockscreen.util import messages

# The record a command line as read resolves to.
Resolved_co = TypeVar("Resolved_co", covariant=True)
Resolved = TypeVar("Resolved")


class _Resolvable(Protocol[Resolved_co]):
    """Protocol for a command line as read whose --as and --as-me can be resolved: userargs.UserArgs and
    runargs.RunArgs.
    """

    @property
    def users(self) -> GivenUsers: ...

    def resolved(self, resolutions: Mapping[UserOption, Resolution]) -> Resolved_co: ...


def screened(parsed: _Resolvable[Resolved], screener: Screener) -> tuple[Report, Resolved | None]:
    """Has the policy judge the users parsed gives and resolve its --as and --as-me
    (Screener.check_given_users, Screener.resolve_given_users); returns the report, and parsed with them
    replaced by ids (userargs.resolved).

    The report holds the refusals, and the record is None; or, if the users pass, the notices of resolving
    them.

    Parameters:
    - parsed: the command line as read (userargs.UserArgs, runargs.RunArgs)
    - screener: the Screener of the command
    """
    refused = screener.check_given_users(parsed.users.given)
    if not refused.passed:
        return refused, None
    resolutions = screener.resolve_given_users(parsed.users.given)
    return Report(tuple(r.notice for r in resolutions.values() if r.notice)), parsed.resolved(resolutions)


def resolve_user_args(args: Sequence[str], value_flags: Collection[str], runtime: Runtime
                      ) -> list[str] | None:
    """Returns args with --as and --as-me replaced by ids (screened), and prints the notices of resolving
    names.

    Returns None, and reports why, if the user cannot be used.

    Parameters:
    - args: the subcommand's arguments
    - value_flags: as userargs.parse takes them
    - runtime: the Runtime of the command, whose accounts and policy the users are resolved and judged with
    """
    read = userargs.parse(args, value_flags, runtime.me, runtime.accounts)
    report, parsed = screened(read, Screener(runtime))
    if parsed is None:
        report.show()
        return None
    for notice in report.notices:
        messages.notice(notice)
    return list(parsed.args)
