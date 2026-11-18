"""This module defines the UserRules class, the group of the policy's rules for the users that containers run
as. It also defines the records that the rules work with:
- IdFacts: the settings and host facts that the id rules judge uids and gids by;
- UserOption: a user that a command line gives;
- Resolution: the user that dockscreen's own --as or --as-me stands for.

Ids. The rules check every id that comes from an untrusted source: `user:` and hook users in a compose
file, and the user an image runs as. Ids from the command line and the config file are trusted, and these
rules do not check them. The rules never accept these, unless they are allowed ids (below):
- 0, root;
- an id that exists on this host: the container would share that account's kernel limits (processes,
  inotify watches), and it would own that account's files in anything it mounts;
- an id in a subordinate range (/etc/subuid, /etc/subgid, any owner): files with these ids belong to
  rootless containers on this host;
- 65535 and 4294967295, which tools read as "no id";
- an id above 2147483647, which docker refuses and older daemons wrap or clamp.

With host mounts (bind mounts, devices, volumes_from, secrets, configs), the id must be an allowed id,
because the id decides which host files the container can write.

The invoking user's own ids are ids on this host too, and they are the most useful ones to a project. A
container that runs as the invoking user can write all of their files that it mounts, such as the
project's .git/hooks; the user later runs those scripts outside any container. A project gets these ids
only with --allow-me, and only for that run.

Allowed ids are:
- the nobody range and the default user, from the config file;
- the ids that the calling code adds for one check (a configured image user);
- the invoking user's own ids, when they gave --allow-me (compose only).

A service's user. `user:` and hook users must be numeric `uid:gid` once dockscreen has resolved the names in
them on this host. They must also pass the id rules (check_user).

An image's user (check_image). The rules judge it from what dockscreen saw of the image
(model.image.ImageInspection), for `docker run` and compose alike. The image is untrusted: its own
/etc/passwd and /etc/group decide the identity that docker would use (see imageuser), and the id rules
decide whether the image may have it. When no user is chosen, the rules decide in this order:
- if the config file names a user for the image's repository, and docker pulled the image from there, the
  image runs as that user, whatever it is (sections.section_for, sections.effective_settings);
- if the image would run as root (uid, gid or a supplementary gid of 0), the default user runs instead,
  with a notice; the default user is the configured one or the nobody user;
- otherwise the image runs as its own user if the id rules accept it, and is refused if they do not.

dockscreen does not leave an accepted user for the runtime to resolve a second time. The container runs as
`uid:gid`, the checked numbers. So if our reading of the image's passwd and group files differs from the
runtime's, the worst outcome is that a good image is refused; root never runs.

The users that a command line gives (check_user_options). The command line is trusted, so the rules judge
only the form of these users. The form must be one that docker cannot read differently from the checked
form. --as and --as-me are dockscreen's own: the rules resolve them to the `--user=uid:gid` that docker gets
(resolve_user_options).

Names in a project. dockscreen resolves names in `user:` and hook users to ids on this host
(resolve_user_names), so that the generated file never asks the image to resolve a name. The method
check_user then checks the ids, and refuses a name that does not exist here.

What runs. dockscreen pins each user that it decided as numbers: `user: "uid:gid"` for compose
(user_changes), and `--user=uid:gid` for `docker run` (user_amendments). The runtime then reads neither passwd
nor group, so it cannot resolve the image's user to anything but the checked user. For compose, dockscreen
pins the checked image too: by id, unless the service builds it, and with `pull_policy: never`. So neither a
pull nor a moved tag can change what runs. `docker run` starts the very container that it checked.

A compose service that does not start and sets no user gets the default user, in case something does start
it: a mistake in working out which services start must fail safe. The default user that replaces root gets
a HOME of its own (default_home), unless someone chose a HOME for it.
"""

import json
from collections.abc import Collection, Iterable, Mapping
from typing import Any, NamedTuple

from dockscreen.host import hostusers
from dockscreen.model.image import ImageInspection, UserIdentity, section_hint
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.policy import imageuser
from dockscreen.policy.commandlinepatch import Amendment, CommandLinePatch
from dockscreen.policy.finding import Finding, Verdict
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.projectpatch import ProjectPatch, Substitution, SubstitutionGroup
from dockscreen.policy.rules.base import JudgedService, RuleBase
from dockscreen.policy.userdecision import UserDecision
from dockscreen.util import commandline, ids

# Current docker refuses larger ids. Older daemons wrap or clamp them, which can give uid 0 or the
# invoking user's own uid, so the rules refuse them here with or without host mounts.
MAX_ID = 2**31 - 1

# The hint that comes with a refusal of an id of the invoking user's, by command: the way to allow it there.
COMPOSE_HINT = f"pass {commandline.ALLOW_ME_OPTION} to allow it"
RUN_HINT = f"pass {commandline.AS_ME_OPTION} to run as you"
# The ways for the command line to choose the user of a container, instead of its image.
CHOOSE_HINT = (f"pass --user UID:GID, {commandline.AS_OPTION} NAME or {commandline.AS_ME_OPTION} to choose a "
               "user")

PINNED_GROUP = SubstitutionGroup(
    "services {services}: user, image id and pull_policy: never fixed to what was checked, "
    "in the generated file only")
USER_HELP = ("set user: on the service to choose one; the default user may not be able to use files and "
             "volumes set up for root")
RESOLVE_HELP = "write the ids (uid:gid) in the project to skip the lookup"


class IdFacts(NamedTuple):
    """Value object for the facts that the id rules (UserRules.id_problems) judge uids and gids by, besides
    the settings of the config file, which the policy holds. The facts are the invoking user's ids and whether
    they are allowed, this host's accounts and subordinate ranges, and the command's hint for allowing the
    invoking user's ids.

    Instances come from Screener.ids, which takes them from the Runtime of the command.

    Attributes:
    - me: the invoking user's (uid, gid)
    - is_me_allowed: whether the invoking user's ids are allowed (--allow-me)
    - local_accounts: the accounts on this host (HostAccounts)
    - subordinate: the ranges in /etc/subuid and /etc/subgid (SubordinateRanges)
    - own_ids_hint: the command's way to allow the invoking user's ids, given after refusing them; empty if
      the command has no way
    """
    me: tuple
    is_me_allowed: bool
    local_accounts: hostusers.HostAccounts
    subordinate: hostusers.SubordinateRanges
    own_ids_hint: str = COMPOSE_HINT


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


class UserRules(RuleBase):
    """Mixin of Policy with the rules for the users that containers run as. It is not used on its own.

    The rules judge a service's user (check_user), an image's user (check_image), and the users that a
    command line gives (check_user_options, resolve_user_options). They also work out the changes that
    follow: names in a project resolved to ids (resolve_user_names), and the decided users pinned in the
    things that run (user_changes, user_amendments).
    """

    def _is_allowed_id(self, kind: str, value: int, allowed_pairs: Iterable[tuple[int, int]] = ()) -> bool:
        """Tells whether value is an allowed id of kind ("uid" or "gid").

        Allowed are the nobody range, and the ids of the default user, of the pairs in allowed_pairs, and of
        the invoking user if is_me_allowed is set.
        """
        index = 0 if kind == "uid" else 1
        low, high = self.nobody_range
        pairs = [self.default_user, *allowed_pairs, *([self.ids.me] if self.ids.is_me_allowed else [])]
        return low <= value <= high or any(pair[index] == value for pair in pairs)

    def id_problem(self, kind: str, value: int, has_mounts: bool,
                   allowed_pairs: Iterable[tuple[int, int]] = ()) -> str | None:
        """Returns the reason that value may not be used as an id of kind, or None if it may.

        Parameters:
        - kind: "uid", "gid" or "supplementary gid"
        - value: the id
        - has_mounts: the container has host mounts, which leaves only allowed ids
        - allowed_pairs: further allowed (uid, gid) pairs
        """
        base = "uid" if kind == "uid" else "gid"
        # first: allowed ids such as the nobody user's usually exist on this host too
        if self._is_allowed_id(base, value, allowed_pairs):
            return None
        if value == 0:
            return f"{kind} 0 is root"
        if value in ids.NO_ID:
            return f"{kind} {value} means \"no id\" to many tools"
        if value > MAX_ID:
            return f"{kind} {value} is above {MAX_ID}, the largest id docker accepts"
        # before the account lookup, which finds the invoking user too, but cannot give the --allow-me hint
        if value == self.ids.me[0 if base == "uid" else 1]:
            hint = self.ids.own_ids_hint
            return f"{kind} {value} is yours" + (f"; {hint}" if hint else "")
        accounts = self.ids.local_accounts
        name = accounts.user_name(value) if base == "uid" else accounts.group_name(value)
        if name is not None:
            account = "user" if base == "uid" else "group"
            return f"{kind} {value} exists on this host (local {account} {name})"
        if self.ids.subordinate.contains(base, value):
            return f"{kind} {value} is in a subordinate id range of this host (rootless containers)"
        if has_mounts:
            low, high = self.nobody_range
            return f"{kind} {value} is not in the nobody range {low}-{high}, and there are host mounts"
        return None

    def id_problems(self, uid: int | None, gid: int | None, supplementary: Iterable[int] = (),
                    has_mounts: bool = False, allowed_pairs: Collection[tuple[int, int]] = ()) -> list[str]:
        """Returns the problems with running as uid, gid and the supplementary gids; empty if there are none.

        Parameters:
        - uid, gid: the ids; None for an id that is not checked
        - supplementary: the supplementary gids
        - has_mounts, allowed_pairs: as id_problem takes them
        """
        checks = [("uid", uid), ("gid", gid), *(("supplementary gid", g) for g in supplementary)]
        problems = [self.id_problem(kind, value, has_mounts, allowed_pairs) for kind,
                    value in checks if value is not None]
        return [p for p in problems if p]

    def check_user(self, value: Any, service: JudgedService) -> list[str]:
        """Checks a `user:` of service, with its names resolved. Returns the problems, and nothing for an
        acceptable `uid:gid`.

        The check refuses a missing user, a name (resolve_user_names resolved the names that exist), a
        missing group, and ids that the id rules refuse. The id rules take into account whether service
        reaches host files, and they allow the configured user.

        Parameters:
        - value: the value of `user:`; None if it is missing
        - service: the service (JudgedService)
        """
        if not value:
            return ["user is not set, the image default may be root"]
        user, colon, group = str(value).partition(":")
        uid, gid = ids.parse_id(user), ids.parse_id(group)
        if uid is None:
            return [_unknown_name_problem("user", user)]
        if not colon:
            # docker would take the group, and supplementary groups, from the image
            return [f"user {value!r} has no group, use uid:gid"]
        if gid is None:
            return [_unknown_name_problem("group", group)]
        configured_pairs = (self.configured_user,) if self.configured_user else ()
        return [f"user {value!r}: {p}"
                for p in self.id_problems(uid, gid, has_mounts=service.reaches_host,
                                          allowed_pairs=configured_pairs)]

    def needs_user_files(self, origin: Origin) -> bool:
        """Tells whether check_image needs the image's passwd and group files (ImageInspection.passwd), for a
        container whose user comes from origin. It needs them only to judge the image's own user, when the
        config file sets no user for the image.
        """
        return origin is Origin.IMAGE and not self.configured_user

    def check_image(self, inspection: ImageInspection, origin: Origin) -> UserDecision:
        """Decides the user that the container may run as, by the rules in this module's docstring. The
        container is the one that inspection looked through. Returns the UserDecision.

        The image section that applies is this policy's (section). If needs_user_files says so, the passwd
        and group files must have been read.

        Parameters:
        - inspection: what was seen of the image (ImageInspection)
        - origin: the origin of the container's user; if it is not the image, this does not judge the user,
          and origin becomes the decision's origin
        """
        image, match = inspection.image, self.section
        notes = (Notice(match.problem, NoticeSeverity.WARNING),) if match.problem else ()
        decision_fields: dict[str, Any] = {"section": match}
        if origin is not Origin.IMAGE:
            return UserDecision(origin, image, notes, **decision_fields)
        if self.configured_user:
            return UserDecision(Origin.CONFIG, image, notes, identity=UserIdentity(*self.configured_user),
                                user=self.configured_user, **decision_fields)
        assert inspection.passwd is not None and inspection.group is not None, "the user files were read"
        try:
            identity = imageuser.resolve(inspection.user, inspection.passwd, inspection.group)
        except ValueError as e:
            return UserDecision(Origin.IMAGE, image, notes, (Finding(str(e)),), **decision_fields)
        if identity.involves_root:
            return UserDecision(self.default_origin, image, notes, identity=identity, user=self.default_user,
                                home="" if inspection.is_home_chosen else self.default_home,
                                replaces_root=True,
                                **decision_fields)
        problems = self.id_problems(identity.uid, identity.gid, identity.supplementary,
                                    has_mounts=inspection.reaches_host)
        refusals = tuple(Finding(f"the image's {p}") for p in problems)
        return UserDecision(Origin.IMAGE, image, notes, refusals, identity,
                            user=(identity.uid, identity.gid), **decision_fields)

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

    def resolve_user_names(self, name: str, service: dict[str, Any]) -> ProjectPatch:
        """Returns the patch that replaces the names in the user and the hook users of the service called
        name by their ids on this host (ids.local_accounts), each with its notice.

        Numbers stay as they are, and so do names unknown here; check_user refuses such a name. A uid alone
        stays alone: the policy refuses it rather than give it a guessed group.
        """
        accounts = self.ids.local_accounts
        substitutions = []
        if service.get("user"):
            resolved_spec = _resolve_spec(service["user"], accounts)
            if resolved_spec != service["user"]:
                message = _resolved_message("user", service["user"], resolved_spec)
                substitutions.append(Substitution(name, "user", resolved_spec, _resolution_notice(message)))
        for key in ("post_start", "pre_stop"):
            hooks = service.get(key) or []
            resolved_hooks = [_with_resolved_user(hook, accounts) for hook in hooks]
            for hook, resolved_hook in zip(hooks, resolved_hooks):
                if resolved_hook is not hook:
                    message = _resolved_message(f"{key} user", hook["user"], resolved_hook["user"])
                    substitutions.append(Substitution(name, key, resolved_hooks, _resolution_notice(message)))
        return ProjectPatch.of(substitutions)

    def user_changes(self, project: Project, decisions: Mapping[str, UserDecision]) -> ProjectPatch:
        """Returns the patch that turns project into the project to run, by service name. A service that
        starts and sets no user gets its decided user (decisions), pinned to the checked image. A service that
        does not start gets this policy's default user, with its default_home as HOME (the function
        default_home).

        Parameters:
        - project: the project
        - decisions: by service, the UserDecision of each started service that sets no user
        """
        substitutions = []
        for name, service in sorted((project.definition.get("services") or {}).items()):
            service = service or {}
            if service.get("user"):
                continue
            decision = decisions.get(name)
            if decision is None:  # not started by this command
                substitutions += _user_substitutions(name, service, self.default_user, self.default_home,
                                                     self.default_origin)
            elif decision.pins_user:
                substitutions += _pin(name, service, decision)
        return ProjectPatch.of(substitutions)

    def user_amendments(self, decision: UserDecision, image: str) -> CommandLinePatch:
        """Returns the patch that runs a `docker run` container as the user that decision pins
        (UserDecision.pins_user), as numbers. The patch reports the change as a warning if that user is the
        default user, replacing the image's root, and as info otherwise. The default user also gets the
        decision's HOME, if the decision has a HOME.

        Parameters:
        - decision: the decision of the container's image, which pins a user
        - image: the image, as the command line names it
        """
        user = ids.format_user(decision.pinned_user)
        args = (f"--user={user}",)
        if not decision.replaces_root:
            return CommandLinePatch.of([Amendment(args, Notice(
                f"image {image} runs as {user}, passed to docker as numbers", NoticeSeverity.INFO))])
        home = default_home(decision.pinned_user, decision.home)
        amendments = [Amendment(args, Notice(
            instead_of_root(decision), NoticeSeverity.WARNING,
            help=f"the default user replaces root; {CHOOSE_HINT}; files and volumes set up for root may not "
            "be accessible to it" + (f", and its HOME is set to {home} unless you set it" if home else "")))]
        if home:
            amendments.append(Amendment(("-e", f"HOME={home}")))  # reported with the user
        return CommandLinePatch.of(amendments)


def image_problem(name: str, decision: UserDecision, config_file: str | None = None) -> Finding:
    """Returns, as one finding, the reason that the service called name must not run. decision is the
    decision of the service's image, which refused or failed.

    Parameters:
    - name: the service's name
    - decision: the UserDecision of its image
    - config_file: named in the hint for a pulled image, since the config file can give its repository a
      user
    """
    image = decision.image
    text = f"image {image.reference}: {'; '.join(r.text for r in decision.findings)}"
    if decision.has_failed:
        return Finding(text, Verdict.FAILED, f"service {name}")
    hint = section_hint(image.reference, config_file, image.is_built) if config_file else None
    return Finding(text, Verdict.REFUSED, f"service {name}",
                   "set user: to choose one" + (f", or {hint}" if hint else ""))


def _unknown_name_problem(kind: str, value: str) -> str:
    """Returns the problem with a user or group (kind) value that is still a name after resolve_user_names.

    UserRules.resolve_user_names resolves every name that exists on this host, so this name does not exist
    here.
    """
    return (f"{kind} {value!r} does not exist on this host (names are resolved on this host, "
            "never in the image)")


# The default user owns nothing of the image's, and the image's HOME (root's, usually) is not its own.
def default_home(user: tuple[int, int], home: str) -> str:
    """Returns the HOME for a default user (uid, gid) that replaces an image's root user, or "" for no HOME.

    Root keeps its own HOME.

    Parameters:
    - user: the default user's (uid, gid)
    - home: the configured default_home
    """
    return "" if 0 in user else home


def _user_substitutions(name: str, service: dict[str, Any], user: tuple[int, int], home: str,
                        origin: Origin | None, text: str | None = None,
                        group: SubstitutionGroup | None = None) -> list[Substitution]:
    """Returns the substitutions that set the service's user to the default user, whose origin is origin.
    If text is given, it reports the change. The substitutions also set the HOME that comes with the default
    user
    (default_home), unless the service sets HOME.
    """
    notice = Notice(text, NoticeSeverity.WARNING, help=USER_HELP) if text else None
    substitutions = [Substitution(name, "user", ids.format_user(user), notice, group=group, origin=origin)]
    if home := default_home(user, home):
        environment = {"HOME": home, **(service.get("environment") or {})}
        substitutions.append(Substitution(name, "environment", environment))
    return substitutions


def _pin(name: str, service: dict[str, Any], decision: UserDecision) -> list[Substitution]:
    """Returns the substitutions that pin a started service to the checks that the decision of its image
    made. The substitutions pin the user, as numbers, and the image, by id, unless the service builds it.
    They also set pull_policy to never.
    """
    if decision.replaces_root:
        substitutions = _user_substitutions(name, service, decision.pinned_user, decision.home,
                                            decision.origin, instead_of_root(decision), PINNED_GROUP)
    else:  # the image's user, or the user that its image section configures
        substitutions = [Substitution(name, "user", ids.format_user(decision.pinned_user), group=PINNED_GROUP,
                                      origin=decision.origin)]
    # The checked image is the one that runs. Between the check and `up`, the project's own pull_policy, a
    # build, or anyone who can tag images on this daemon could point the name at another image. Nothing has
    # decided the user of that image, which may be root. Never pulling, and naming the image by id, close
    # that gap.
    substitutions.append(Substitution(name, "pull_policy", "never", group=PINNED_GROUP,
                                      origin=Origin.DOCKSCREEN))
    if decision.image.id and "build" not in service:
        # ... even if someone moves the name to another image
        substitutions.append(Substitution(name, "image", decision.image.id, group=PINNED_GROUP,
                                          origin=Origin.DOCKSCREEN))
    return substitutions


def _resolution_notice(message: str) -> Notice:
    """Returns the notice that reports message, which says that a name was resolved to ids."""
    return Notice(message, NoticeSeverity.INFO, help=RESOLVE_HELP)


def _with_resolved_user(hook: Any, accounts: hostusers.HostAccounts) -> Any:
    """Returns hook with the names in its user resolved to ids. Returns hook itself if there is nothing to
    resolve.
    """
    if not (isinstance(hook, dict) and hook.get("user")):
        return hook
    resolved_spec = _resolve_spec(hook["user"], accounts)
    return hook if resolved_spec == hook["user"] else {**hook, "user": resolved_spec}


def _resolve_spec(spec: object, accounts: hostusers.HostAccounts) -> str:
    """Resolves a user spec: `name` becomes that account's `uid:gid`, and a group name becomes its gid.

    Numbers and unknown names stay. A uid alone stays alone: the policy refuses it rather than guess a group.
    """
    user, colon, group = str(spec).partition(":")
    account = accounts.user_ids(user) if user and ids.parse_id(user) is None else None
    uid = str(account[0]) if account else user
    if colon:
        gid = _resolve_group(group, accounts)
    elif account:
        gid = str(account[1])  # a name brings its primary group, as with --as
    else:
        return str(spec) if uid == user else uid
    return f"{uid}:{gid}"


def _resolve_group(group: str, accounts: hostusers.HostAccounts) -> str:
    """Returns group as a gid, if accounts knows its name. Ids and unknown names stay unchanged."""
    if ids.parse_id(group) is not None:
        return group
    gid = accounts.group_id(str(group))
    return group if gid is None else str(gid)


def _resolved_message(what: str, before: object, after: str) -> str:
    """Returns the text of the notice that reports a resolution on this host. The parameter what names the
    value (the user, or a hook's user); before is that value before the resolution, and after is the value
    after it.
    """
    return f"{what} {json.dumps(before)} resolved to {json.dumps(after)} on this host"


def instead_of_root(decision: UserDecision) -> str:
    """Describes the user that runs instead of root, for a decision that replaces_root."""
    return f"running as {ids.format_user(decision.pinned_user)} instead of root"
