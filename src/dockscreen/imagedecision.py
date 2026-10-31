"""Deciding the user a container runs as when the command line or the service does not choose one.

The image is untrusted: its own /etc/passwd and /etc/group decide the identity docker would use (see
imageuser), and the id rules decide whether the image may have it (idrules). With no user chosen, in
this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (images.section_for, config.effective);
- the image would run as root (uid, gid or a supplementary gid of 0): the configured default user
  instead, nobody unless configured otherwise, with a notice;
- otherwise the image's own user, if the id rules accept it; refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: it runs as `uid:gid`, the
checked numbers, so a difference between our reading of the image's passwd and group
files and the runtime's can at worst refuse a good image, never run root.

Used by `docker run` (gate) and by compose (composeimages) alike.
"""

import enum
from typing import NamedTuple

from dockscreen import config, idrules, ids, images, imageuser, messages
from dockscreen.dockerclient import Docker
from dockscreen.runtime import Runtime


class Context(NamedTuple):
    docker: Docker
    ids: idrules.Rules
    runtime: Runtime               # the config file, the caller's ids, the host's accounts
    project_dir: str | None = None  # the compose project's; for docker run, the current directory

    @property
    def local(self):
        """Returns the host accounts of the id rules, for naming the users an image runs as."""
        return self.ids.local

    @property
    def directory(self):
        """Returns the directory a bind mount is judged against: the project's, else the current one."""
        return self.project_dir or self.runtime.cwd

    @property
    def settings(self):
        """Returns the config file's settings for this directory's project, without any image section."""
        return config.effective(self.runtime.settings, None, self.directory)

    def for_image(self, repository):
        """Returns (settings, id rules) with the image section for repository applied (None: none applies)."""
        settings = config.effective(self.runtime.settings, repository, self.directory)
        return settings, self.ids.with_settings(settings)

    def with_allow_me(self, allow_me):
        """Returns this context with the caller's own ids allowed if allow_me, for --allow-me and --as-me."""
        return self._replace(ids=self.ids._replace(allow_me=True)) if allow_me else self


class Kind(enum.StrEnum):
    EXPLICIT = "explicit"      # the command line chose the user: trusted, not checked
    CONFIGURED = "configured"  # the config file names the user, for this image, project or every one
    OK = "ok"                  # the image's own user, which the id rules accept
    FALLBACK = "fallback"      # the image would run as root: the default user instead
    REFUSED = "refused"
    FAILED = "failed"          # the image could not be looked at: missing, or docker failed


class Assessment(NamedTuple):
    kind: Kind
    problems: list
    identity: imageuser.Identity | None = None
    note: str | None = None        # a section for the repository that does not apply, and why
    user: tuple | None = None      # the (uid, gid) it runs as, when dockscreen decided it (pins_user)
    section: str | None = None     # the repository whose image section applied, if one did
    home: str = ""                 # the HOME to set for the default user that replaces root; "": leave it

    @property
    def refused(self):
        """Tells whether the container must not run: refused, or not assessed at all."""
        return self.kind in (Kind.REFUSED, Kind.FAILED)

    @property
    def failed(self):
        """Tells whether the image could not be assessed at all."""
        return self.kind is Kind.FAILED

    @property
    def pins_user(self):
        """Tells whether dockscreen decided the user, and runs the image as it, spelled as numbers."""
        return self.kind in (Kind.CONFIGURED, Kind.OK, Kind.FALLBACK)

    @property
    def replaces_image_user(self):
        """Tells whether the user dockscreen decided differs from the one the image chose."""
        return self.kind in (Kind.CONFIGURED, Kind.FALLBACK)


def _has_host_mounts(info):
    """Tells whether the container, as inspected, reaches host files or devices.

    Bind mounts, devices and volumes taken from another container all do. Named volumes live in
    docker's own directory and tmpfs in memory, so the user id means nothing to the host there.
    """
    host = info.get("HostConfig") or {}
    mounts = [*(info.get("Mounts") or []), *(host.get("Mounts") or [])]
    # a Binds source that is not a path names a volume
    binds = [b for b in host.get("Binds") or [] if str(b).split(":")[0].startswith("/")]
    binds_or_devices = any(m.get("Type") == "bind" for m in mounts) or binds
    return bool(binds_or_devices or host.get("Devices") or host.get("VolumesFrom"))


def assess(ctx, container, info, explicit=None, mounts=None, reference=None, built=False):
    """Decides which user the container's image may run as, by the rules in this module's docstring.

    Returns an Assessment. Raises DockerError if the image cannot be inspected or its passwd or group
    file is too large.
    explicit: the user was set on the command line, if known.
    mounts: the container reaches host files or devices; worked out from info if not given.
    reference: the image name as the command line or the service gave it (the container's if None).
    built: the image is built from a Dockerfile by the service; the config file never applies then.
    """
    image = ctx.docker.inspect_image(info["Image"])
    match = images.section_for(ctx.runtime.settings, reference or info["Config"].get("Image") or "",
                               image.get("RepoDigests"), built)
    found = {"note": match.problem, "section": match.repository}
    spec = info["Config"].get("User") or ""
    if explicit is None:  # the container's user differs from the image's only if the command line set one
        explicit = spec != (image["Config"].get("User") or "")
    if explicit:
        return Assessment(Kind.EXPLICIT, [], **found)  # trusted: the person typing the command chose it

    settings, rules = ctx.for_image(match.repository)
    if settings.user:
        return Assessment(Kind.CONFIGURED, [], imageuser.Identity(*settings.user, ()), user=settings.user,
                          **found)

    # a missing file has no names in it, for docker as for us
    passwd = ctx.docker.read_file(container, "/etc/passwd") or ""
    groups = ctx.docker.read_file(container, "/etc/group") or ""
    try:
        identity = imageuser.resolve(spec, passwd, groups)
    except ValueError as e:
        return Assessment(Kind.REFUSED, [str(e)], **found)
    if imageuser.involves_root(identity):
        return Assessment(Kind.FALLBACK, [], identity, user=settings.default_user, home=settings.default_home,
                          **found)
    if mounts is None:
        mounts = _has_host_mounts(info)
    problems = rules.problems(identity.uid, identity.gid, identity.supplementary, mounts=mounts)
    if problems:
        return Assessment(Kind.REFUSED, [f"the image's {p}" for p in problems], identity, **found)
    return Assessment(Kind.OK, [], identity, user=(identity.uid, identity.gid), **found)


# The default user owns nothing of the image's, and the image's HOME (root's, usually) is not its own.
def default_home(user, home):
    """Returns the HOME for a default user (uid, gid) that replaces an image's root user, or "" for none.

    home: the configured default_home. Root keeps its own.
    """
    return "" if 0 in user else home


def env_value(env, name):
    """Returns the value the last `name=` entry of an `Env` list of `NAME=value` strings sets, or None."""
    for entry in reversed(env or []):
        key, equals, value = entry.partition("=")
        if equals and key == name:
            return value
    return None


def runs_as(assessment, local):
    """Describes what an accepted image (Kind.OK or Kind.CONFIGURED) runs as; local: HostAccounts."""
    if assessment.kind is Kind.CONFIGURED:
        return f"runs as {ids.format_user(assessment.user)}, the user the config file sets for it"
    return f"runs as {imageuser.describe(assessment.identity, local)}; accepted"


def instead_of_root(assessment):
    """Describes what a Kind.FALLBACK assessment does instead of running as root."""
    return f"running as {ids.format_user(assessment.user)} instead of root"


def root_default_notice(ctx):
    """Returns the warning to give on every run if the configured default user is root, else None."""
    if 0 in ctx.settings.default_user:
        default = ids.format_user(ctx.settings.default_user)
        return messages.Marked(
            messages.WARN,
            f"the configured default user is {default}: images that would run as root run as root",
            "set default_user in the config file to change it")
    return None
