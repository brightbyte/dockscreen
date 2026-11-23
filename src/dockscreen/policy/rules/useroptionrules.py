"""This module defines the UserOptionRules class, the group of the policy's rules for the users that a
command line gives. It also defines the records that the rules work with:
- UserOption: a user that a command line gives;
- Resolution: the user that dockscreen's own --as or --as-me stands for.

The command line is trusted, so the rules judge only the form of these users. The form must be one that
docker cannot read differently from the checked form. --as and --as-me are dockscreen's own: the rules
resolve them to the `--user=uid:gid` that docker gets (resolve_user_options).
"""

from collections.abc import Iterable
from typing import NamedTuple

from dockscreen.policy.finding import Finding
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.rules.base import RuleBase
from dockscreen.util import commandline, ids


class UserOption(NamedTuple):
    """Record of one user option that a command line gives, for the policy to judge. It holds the option and
    its value. For --as and --as-me, it also holds the ids that they stand for on this host.

    userargs and runargs read command lines. In the arguments they produce, --as and --as-me stay as their
    UserOption until the rules resolve them (resolve_user_options).

    Attributes:
    - flag: `--user`, `--as` or `--as-me`
    - value: the option's value; "" for --as-me
    - account: the (uid, gid) of the account that --as names on this host, or the invoking user's for
      --as-me; None if there is no such account, and for --user
    """
    flag: str
    value: str
    account: tuple[int, int] | None = None


class Resolution(NamedTuple):
    """Record of the user that --as or --as-me stands for, and the notice that reports it.

    Attributes:
    - user: the user as `uid:gid`, which docker gets as `--user=uid:gid`
    - notice: the notice that reports the resolution, or None if there is nothing to say
    """
    user: str
    notice: Notice | None = None


# The ways to choose a user on a docker command line, named in refusals of --user.
USER_OPTION_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"


class UserOptionRules(RuleBase):
    """Mixin of Policy with the rules for the users that a command line gives. It is not used on its own.

    The rules judge the users (check_user_options), and resolve --as and --as-me to ids
    (resolve_user_options).
    """

    def check_user_options(self, options: Iterable[UserOption]) -> list[Finding]:
        """Checks the users a command line gives (check_user_option, check_as_option); returns the
        refusals.
        """
        findings = []
        for option in options:
            if option.flag == commandline.AS_OPTION:
                findings += self.check_as_option(option.value, option.account)
            elif option.flag == "--user":
                findings += self.check_user_option(option.value)
        return findings

    def resolve_user_options(self, options: Iterable[UserOption]) -> dict[UserOption, Resolution]:
        """Returns the user that each --as and --as-me of options stands for. For --as, it is the ids of the
        account that --as names, with a notice; for --as-me, it is the invoking user's own ids. An --as
        without an account is left out, because check_user_options refuses it. --user is left out too,
        because docker gets it as given.
        """
        resolutions = {}
        for option in options:
            if option.flag == commandline.AS_ME_OPTION and option.account:
                resolutions[option] = Resolution(ids.format_user(option.account))
            elif option.flag == commandline.AS_OPTION and option.account:
                uid, gid = option.account
                notice = Notice(f"Resolving user {option.value} to uid {uid}, gid {gid}", NoticeSeverity.INFO)
                resolutions[option] = Resolution(ids.format_user(option.account), notice)
        return resolutions

    def check_user_option(self, spec: str) -> list[Finding]:
        """Checks a user that --user or -u gives. Returns a refusal unless it is numeric `uid:gid`.

        Docker would resolve a name in the image, or, for exec, in the running container; the image controls
        both. A uid alone would leave the group to the image: docker takes the group and the supplementary
        groups from the image's own passwd and group files, and those can say root.
        """
        if ids.parse_user(spec):
            return []
        hint = "; give the group too, as uid:gid" if ids.is_id(spec) else ""
        return [Finding(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}{USER_OPTION_ALTERNATIVES}")]

    def check_as_option(self, name: str, account: tuple[int, int] | None) -> list[Finding]:
        """Checks the name that --as gives, and the account of that name on this host. Returns a refusal
        unless the name names an account here.

        Parameters:
        - name: what --as gives
        - account: the (uid, gid) of the account of that name here; None if there is no such account
        """
        if not name or ":" in name or ids.is_id(name):
            return [Finding(f"--as takes the name of a local user, not {name!r}; use --user for ids")]
        if account is None:
            return [Finding(f"user {name!r} does not exist on this host; use --user with a numeric id")]
        return []
