"""This module defines the UserRules class, the group of the policy's rules for the users containers run as,
and what they work with: IdRules, which decides which uids and gids a project or an image may choose,
UserOption, the record of a user a command line gives, and Resolution, what dockscreen's own --as and --as-me
stand for.

Ids. Every id that comes from an untrusted source is checked: `user:` and hook users in a compose file, and
the user an image runs as. Ids from the command line and the config file are trusted and are not checked
against these rules. Never accepted, unless they are allowed ids (below):
- 0, root;
- an id that exists on this host: the container would share that account's kernel limits
  (processes, inotify watches), and own its files in anything it mounts;
- an id in a subordinate range (/etc/subuid, /etc/subgid, any owner): files with these ids belong to
  rootless containers on this host;
- 65535 and 4294967295, which tools read as "no id";
- an id above 2147483647, which docker refuses and older daemons wrap or clamp.

With host mounts (bind mounts, devices, volumes_from, secrets, configs) the id must be an allowed id,
because what the container can write on the host depends on it.

Allowed ids: the nobody range and the default user from the config file, ids the caller adds for one
check (a configured image user), and the caller's own ids when --allow-me was given (compose).

A service's user. `user:` and hook users must be numeric `uid:gid` once hardening has resolved names on this
host, and pass the id rules (check_user).

An image's user, from what was seen of the image (model.image.Inspected), for `docker run` and compose alike
(check_image). The image is untrusted: its own /etc/passwd and /etc/group decide the identity docker would use
(see imageuser), and the id rules decide whether the image may have it. With no user chosen, in this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (config.section_for, config.effective);
- the image would run as root (uid, gid or a supplementary gid of 0): the default user instead, the
  configured one or nobody, with a notice;
- otherwise the image's own user, if the id rules accept it; refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: it runs as `uid:gid`, the
checked numbers, so a difference between our reading of the image's passwd and group files and the
runtime's can at worst refuse a good image, never run root.

The users a command line gives (check_user_options). Only their form is judged, since the command line is
trusted, but in a form docker cannot read differently from what was checked. --as and --as-me are
dockscreen's own: the rules resolve them to the `--user=uid:gid` docker gets (resolve_user_options).
"""

from collections.abc import Collection, Iterable
from typing import Any, NamedTuple, Self

from dockscreen.host import config as configuration
from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime
from dockscreen.model.image import Inspected, UserIdentity, section_hint
from dockscreen.model.origin import Origin
from dockscreen.screen import imageuser
from dockscreen.screen.findings import Finding, Verdict
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.rules.base import JudgedService, RuleBase
from dockscreen.screen.userdecision import UserDecision
from dockscreen.util import commandline, ids

# Current docker refuses larger ids. Older daemons wrap or clamp them, which can give uid 0 or the
# caller's own uid, so they are refused here with or without host mounts.
MAX_ID = 2**31 - 1

# What an id of the caller's is refused with, by the command: how it can be allowed there.
COMPOSE_HINT = f"pass {commandline.ALLOW_ME} to allow it"
RUN_HINT = f"pass {commandline.AS_ME} to run as you"


class IdRules(NamedTuple):
    """Value object for deciding which uids and gids a project or an image may choose (problems). It holds the
    caller's ids and whether they are allowed, the nobody range and the default user from the config file, and
    this host's accounts and subordinate ranges.

    Instances come from for_runtime; with_settings gives a copy.

    Attributes:
    - me: the caller's (uid, gid)
    - allow_me: whether the caller's ids are allowed (--allow-me)
    - nobody_range: the inclusive (low, high) range of ids any project or image may choose
    - default_user: the (uid, gid) that replaces root
    - local: the accounts on this host (HostAccounts)
    - subordinate: the ranges in /etc/subuid and /etc/subgid (SubordinateRanges)
    - own_ids_hint: how the command allows the caller's ids, said after refusing them; empty if it has no way
    """
    me: tuple
    allow_me: bool
    nobody_range: tuple
    default_user: tuple
    local: hostusers.HostAccounts
    subordinate: hostusers.SubordinateRanges
    own_ids_hint: str = COMPOSE_HINT

    @classmethod
    def for_runtime(cls, runtime: Runtime, allow_me: bool = False, own_ids_hint: str = COMPOSE_HINT) -> Self:
        """Returns the id rules for the config file's settings.

        Parameters:
        - runtime: the Runtime of the command, whose settings and caller give the rules
        - allow_me: the caller's own ids are allowed
        - own_ids_hint: how the command allows them, for the refusal
        """
        return cls(runtime.me, allow_me, runtime.settings.nobody_range, runtime.settings.default_user,
                   runtime.accounts, runtime.subordinate, own_ids_hint)

    def with_settings(self, settings: configuration.Config) -> Self:
        """Returns these rules with the nobody range and default user of settings (config.effective)."""
        return self._replace(nobody_range=settings.nobody_range, default_user=settings.default_user)

    def _allowed(self, kind: str, value: int, extra: Iterable[tuple[int, int]] = ()) -> bool:
        """Tells whether value is an allowed id of kind ("uid" or "gid").

        Allowed are the nobody range, and the ids of the default user, of the pairs in extra, and of the
        caller if allow_me is set.
        """
        index = 0 if kind == "uid" else 1
        low, high = self.nobody_range
        pairs = [self.default_user, *extra, *([self.me] if self.allow_me else [])]
        return low <= value <= high or any(pair[index] == value for pair in pairs)

    def problem(self, kind: str, value: int, mounts: bool,
                extra: Iterable[tuple[int, int]] = ()) -> str | None:
        """Returns why value may not be used as an id of kind, or None if it may.

        Parameters:
        - kind: "uid", "gid" or "supplementary gid"
        - value: the id
        - mounts: the container has host mounts, which leaves only allowed ids
        - extra: further allowed (uid, gid) pairs
        """
        base = "uid" if kind == "uid" else "gid"
        # first: allowed ids such as nobody usually exist on this host too
        if self._allowed(base, value, extra):
            return None
        if value == 0:
            return f"{kind} 0 is root"
        if value in configuration.NO_ID:
            return f"{kind} {value} means \"no id\" to many tools"
        if value > MAX_ID:
            return f"{kind} {value} is above {MAX_ID}, the largest id docker accepts"
        # before the account lookup, which finds the caller too but cannot give the --allow-me hint
        if value == self.me[0 if base == "uid" else 1]:
            return f"{kind} {value} is yours" + (f"; {self.own_ids_hint}" if self.own_ids_hint else "")
        name = self.local.user_name(value) if base == "uid" else self.local.group_name(value)
        if name is not None:
            account = "user" if base == "uid" else "group"
            return f"{kind} {value} exists on this host (local {account} {name})"
        if self.subordinate.contains(base, value):
            return f"{kind} {value} is in a subordinate id range of this host (rootless containers)"
        if mounts:
            low, high = self.nobody_range
            return f"{kind} {value} is not in the nobody range {low}-{high}, and there are host mounts"
        return None

    def problems(self, uid: int | None, gid: int | None, supplementary: Iterable[int] = (),
                 mounts: bool = False, extra: Collection[tuple[int, int]] = ()) -> list[str]:
        """Returns the problems with running as uid, gid and the supplementary gids; empty if there are none.

        Parameters:
        - uid, gid: the ids; None for one that is not checked
        - supplementary: the supplementary gids
        - mounts, extra: as problem takes them
        """
        checks = [("uid", uid), ("gid", gid), *(("supplementary gid", g) for g in supplementary)]
        found = [self.problem(kind, value, mounts, extra) for kind, value in checks if value is not None]
        return [p for p in found if p]


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


class UserRules(RuleBase):
    """Mixin of Policy with the rules for the users containers run as, not used on its own: a service's user
    (check_user), an image's user (check_image) and the users a command line gives (check_user_options,
    resolve_user_options).
    """

    def check_user(self, value: Any, service: JudgedService) -> list[str]:
        """Checks a `user:` of service as hardening left it; returns the problems, empty for an acceptable
        `uid:gid`.

        Refused are a missing user, a name (hardening resolved those that exist), a missing group, and ids
        the id rules refuse (ids, with whether service reaches host files and the configured user allowed).

        Parameters:
        - value: the value of `user:`; None if it is missing
        - service: the service (JudgedService)
        """
        if not value:
            return ["user is not set, the image default may be root"]
        user, has_group, group = str(value).partition(":")
        uid, gid = ids.parse_id(user), ids.parse_id(group)
        if uid is None:
            return [_not_a_name("user", user)]
        if not has_group:
            # docker would take the group, and supplementary groups, from the image
            return [f"user {value!r} has no group, use uid:gid"]
        if gid is None:
            return [_not_a_name("group", group)]
        configured = (self.configured_user,) if self.configured_user else ()
        return [f"user {value!r}: {p}"
                for p in self.ids.problems(uid, gid, mounts=service.reaches_host, extra=configured)]

    def needs_user_files(self, origin: Origin) -> bool:
        """Tells whether check_image needs the image's passwd and group files (Inspected.passwd) for a
        container whose user comes from origin: only to judge the image's own user, when the config file
        sets none for it.
        """
        return origin is Origin.IMAGE and not self.configured_user

    def check_image(self, inspected: Inspected, origin: Origin) -> UserDecision:
        """Decides which user the container that inspected looked through may run as, by the rules in this
        module's docstring; returns the UserDecision.

        The image section that applies is this policy's (section). The passwd and group files must have been
        read if needs_user_files says so.

        Parameters:
        - inspected: what was seen of the image (Inspected)
        - origin: where the container's user comes from; one that is not the image's is not judged here, and
          is the decision's origin
        """
        image, match = inspected.image, self.section
        notes = (Notice(match.problem, NoticeSeverity.WARNING),) if match.problem else ()
        found: dict[str, Any] = {"section": match}
        if origin is not Origin.IMAGE:
            return UserDecision(origin, image, notes, **found)
        if self.configured_user:
            return UserDecision(Origin.CONFIG, image, notes, identity=UserIdentity(*self.configured_user),
                                user=self.configured_user, **found)
        assert inspected.passwd is not None and inspected.group is not None, "the user files were read"
        try:
            identity = imageuser.resolve(inspected.user, inspected.passwd, inspected.group)
        except ValueError as e:
            return UserDecision(Origin.IMAGE, image, notes, (Finding(str(e)),), **found)
        if identity.involves_root:
            return UserDecision(self.default_origin, image, notes, identity=identity, user=self.default_user,
                                home="" if inspected.home_chosen else self.default_home, replaces_root=True,
                                **found)
        problems = self.ids.problems(identity.uid, identity.gid, identity.supplementary,
                                     mounts=inspected.reaches_host)
        refusals = tuple(Finding(f"the image's {p}") for p in problems)
        return UserDecision(Origin.IMAGE, image, notes, refusals, identity,
                            user=(identity.uid, identity.gid), **found)

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


def image_problem(name: str, decision: UserDecision, config_file: str | None = None) -> Finding:
    """Returns, as one finding, why the service called name must not run, for a decision of its image
    that refused or failed.

    Parameters:
    - name: the service's name
    - decision: the UserDecision of its image
    - config_file: named in the hint for an image that is pulled, whose repository can be given a user
    """
    image = decision.image
    text = f"image {image.reference}: {'; '.join(r.text for r in decision.findings)}"
    if decision.failed:
        return Finding(text, Verdict.FAILED, f"service {name}")
    hint = section_hint(image.reference, config_file, image.built) if config_file else None
    return Finding(text, Verdict.REFUSED, f"service {name}",
                   "set user: to choose one" + (f", or {hint}" if hint else ""))


def _not_a_name(kind: str, value: str) -> str:
    """Returns the problem with a user or group (kind) value that is still a name after hardening.

    Hardening resolves every name that exists on this host, so this one does not.
    """
    return (f"{kind} {value!r} does not exist on this host (names are resolved on this host, "
            "never in the image)")

