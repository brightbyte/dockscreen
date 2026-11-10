"""This module defines the CommandLineRules class, the group of the policy's rules for the users a command
line gives, UserOption, the record of one, and Resolution, what dockscreen's own options stand for. Only
their form is judged, since the command line is trusted, but in a form docker cannot read differently from
what was checked. --as and --as-me are dockscreen's own: the rules resolve them to the `--user=uid:gid`
docker gets.
"""

from collections.abc import Iterable
from typing import NamedTuple

from dockscreen.screen.findings import Finding
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.rules.base import RuleBase
from dockscreen.util import commandline, ids


class UserOption(NamedTuple):
    """Record of one user option a command line gives, for the policy to judge. It holds the option and its
    value, and for --as and --as-me the ids they stand for on this host.

    In the arguments of a command line read by userargs or runargs, --as and --as-me are kept as their
    UserOption until they are resolved (resolve_user_options).

    Attributes:
    - flag: `--user`, `--as` or `--as-me`
    - value: what the option gives; "" for --as-me
    - account: the (uid, gid) of the account --as names on this host, or the caller's for --as-me; None if
      there is none, and for --user
    """
    flag: str
    value: str
    account: tuple[int, int] | None = None


class Resolution(NamedTuple):
    """Record of the user that --as or --as-me stands for, and the notice that reports it.

    Attributes:
    - user: the user as `uid:gid`, which docker gets as `--user=uid:gid`
    - notice: what was resolved, or None if there is nothing to say
    """
    user: str
    notice: Notice | None = None


# The ways to choose a user on a docker command line, named in refusals of --user.
USER_OPTION_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"


class CommandLineRules(RuleBase):
    """Mixin of Policy with the rules for the users a command line gives, not used on its own."""

    def check_user_options(self, options: Iterable[UserOption]) -> list[Finding]:
        """Checks the users a command line gives (check_user_option, check_as_option); returns the
        refusals.
        """
        found = []
        for option in options:
            if option.flag == commandline.AS:
                found += self.check_as_option(option.value, option.account)
            elif option.flag == "--user":
                found += self.check_user_option(option.value)
        return found

    def resolve_user_options(self, options: Iterable[UserOption]) -> dict[UserOption, Resolution]:
        """Returns what each --as and --as-me of options stands for: the ids of the account --as names, with a
        notice, and the caller's own for --as-me. An --as without an account, which check_user_options
        refuses, is left out; so is --user, which docker gets as given.
        """
        found = {}
        for option in options:
            if option.flag == commandline.AS_ME and option.account:
                found[option] = Resolution(ids.format_user(option.account))
            elif option.flag == commandline.AS and option.account:
                uid, gid = option.account
                notice = Notice(f"Resolving user {option.value} to uid {uid}, gid {gid}", NoticeSeverity.INFO)
                found[option] = Resolution(ids.format_user(option.account), notice)
        return found

    def check_user_option(self, spec: str) -> list[Finding]:
        """Checks a user that --user or -u gives; returns a refusal unless it is numeric `uid:gid`.

        A name would be resolved in the image, or for exec in the running container, which the image
        controls. A uid alone would leave the group to the image: docker takes it, and the supplementary
        groups, from the image's own passwd and group files, which can say root.
        """
        if ids.parse_user(spec):
            return []
        hint = "; give the group too, as uid:gid" if ids.is_id(spec) else ""
        return [Finding(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}{USER_OPTION_ALTERNATIVES}")]

    def check_as_option(self, name: str, account: tuple[int, int] | None) -> list[Finding]:
        """Checks the name that --as gives and the account of that name on this host;
        returns a refusal unless it names an account here.

        Parameters:
        - name: what --as gives
        - account: the (uid, gid) of the account of that name here; None if there is none
        """
        if not name or ":" in name or ids.is_id(name):
            return [Finding(f"--as takes the name of a local user, not {name!r}; use --user for ids")]
        if account is None:
            return [Finding(f"user {name!r} does not exist on this host; use --user with a numeric id")]
        return []
