"""This module defines the policy's rules for the users a command line gives: only their form, since the
command line is trusted, but in a form docker cannot read differently from what was checked.
"""

from collections.abc import Iterable
from typing import NamedTuple

from dockscreen.screen.findings import Finding
from dockscreen.screen.rules.base import RuleBase
from dockscreen.util import ids


class UserOption(NamedTuple):
    """User a command line gives: --user with its value, or --as with the name and the account of that name
    on this host (None: there is none).
    """
    flag: str
    value: str
    account: tuple[int, int] | None = None


# The ways to choose a user on a docker command line, named in refusals of --user.
USER_OPTION_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"


class CommandLineRules(RuleBase):
    """Rules for the users a command line gives."""

    def check_user_options(self, options: Iterable[UserOption]) -> list[Finding]:
        """Checks the users a command line gives (check_user_option, check_as_option); returns the
        refusals.
        """
        found = []
        for option in options:
            if option.flag == "--as":
                found += self.check_as_option(option.value, option.account)
            else:
                found += self.check_user_option(option.value)
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
        """Checks the name that --as gives and the account of that name on this host (None: there is none);
        returns a refusal unless it names an account here.
        """
        if not name or ":" in name or ids.is_id(name):
            return [Finding(f"--as takes the name of a local user, not {name!r}; use --user for ids")]
        if account is None:
            return [Finding(f"user {name!r} does not exist on this host; use --user with a numeric id")]
        return []
