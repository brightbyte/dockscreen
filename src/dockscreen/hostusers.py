"""The accounts on this host, and users given on the command line: ids as typed, or a local account.

Docker resolves a user name in the container's own /etc/passwd, where an image can map it
to root. So `--user` takes only numbers, which mean the same everywhere, and `--as NAME` takes the
name of an account on this host and turns it into ids before docker sees it.
"""

import grp
import pwd
from dockscreen import ids


class UserError(Exception):
    """A user given on the command line cannot be used."""


class UnknownUser(UserError):
    pass


DOCKER_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"


def _require_numeric(spec, alternatives=DOCKER_ALTERNATIVES):
    """Returns spec as typed if it is numeric `uid:gid`; raises UserError saying what to use otherwise.

    A uid alone would leave the group to the image: docker takes it, and the supplementary groups,
    from the image's own passwd and group files, which can say root.
    """
    if ids.parse_user(spec):
        return spec
    hint = "; give the group too, as uid:gid" if ids.is_id(spec) else ""
    raise UserError(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}{alternatives}")


def _resolve_account(name, accounts):
    """Resolves name to the account of that name on this host; returns (`uid:gid`, notices).

    The gid is the account's primary group. accounts: where to look the name up (HostAccounts).
    Raises UserError for an empty name, an id or a `:`, UnknownUser if there is no such account.
    """
    if not name or ":" in name or ids.is_id(name):
        raise UserError(f"--as takes the name of a local user, not {name!r}; use --user for ids")
    account = accounts.user(name)
    if account is None:
        raise UnknownUser(f"user {name!r} does not exist on this host; use --user with a numeric id")
    uid, gid = account
    return ids.format_user(account), [f"Resolving user {name} to uid {uid}, gid {gid}"]


class UserOptions:
    """The ways a command line gives a user, each turned into `--user=uid:gid` for docker.

    Records whether a user was given, whether the caller's own ids are allowed (--as-me), and the
    notices that resolving names produced.
    """

    def __init__(self, me, accounts):
        """Starts with no user given; me: the (uid, gid) --as-me stands for; accounts: where --as looks."""
        self.callers_ids = me
        self.accounts = accounts
        self.user_given = False
        self.allow_me = False
        self.notices = []

    def numeric(self, spec):
        """Returns `--user=` for spec (--user or -u); raises UserError unless it is numeric `uid:gid`."""
        self.user_given = True
        return f"--user={_require_numeric(spec)}"

    def account(self, name):
        """Returns `--user=` with the ids of the local account called name (--as), and keeps the notice.

        Raises UserError if there is no such account (_resolve_account).
        """
        self.user_given = True
        resolved, messages = _resolve_account(name, self.accounts)
        self.notices += messages
        return f"--user={resolved}"

    def me(self):
        """Returns `--user=` with the caller's own ids (--as-me), and records that those are allowed."""
        self.user_given = self.allow_me = True
        return f"--user={ids.format_user(self.callers_ids)}"


class HostAccounts:
    """Users and groups on this host, through NSS (so LDAP and sssd accounts count)."""

    def user(self, name):
        """Returns (uid, primary gid) of the user called name, or None if there is none."""
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            return None
        return account.pw_uid, account.pw_gid

    def group(self, name):
        """Returns the gid of the group called name, or None if there is none."""
        try:
            return grp.getgrnam(name).gr_gid
        except KeyError:
            return None

    def user_name(self, uid):
        """Returns the name of the user with this uid, or None if there is none."""
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return None

    def group_name(self, gid):
        """Returns the name of the group with this gid, or None if there is none."""
        try:
            return grp.getgrgid(gid).gr_name
        except KeyError:
            return None
