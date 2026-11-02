"""This module decides which user a container runs as and whether it may: the user chosen for it, or else
one derived from its image under the id rules. It looks at the image as far as the policy needs, and the
policy judges it (Policy.check_image); the rest of this module says what was decided.

The image is untrusted: its own /etc/passwd and /etc/group decide the identity docker would use (see
imageuser), and the id rules decide whether the image may have it (idrules). With no user chosen, in
this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (config.section_for, config.effective);
- the image would run as root (uid, gid or a supplementary gid of 0): the configured default user
  instead, nobody unless configured otherwise, with a notice;
- otherwise the image's own user, if the id rules accept it; refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: it runs as `uid:gid`, the
checked numbers, so a difference between our reading of the image's passwd and group
files and the runtime's can at worst refuse a good image, never run root.

Used by `docker run` (docker_run) and by compose (serviceusers) alike.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.host import config, hostusers, inspection
from dockscreen.model.origin import Origin
from dockscreen.screen import imageuser
from dockscreen.screen.assessment import Assessment, Kind
from dockscreen.screen.findings import Finding
from dockscreen.screen.scope import Scope
from dockscreen.util import ids, images, messages

CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"


def assess(ctx: Scope, directory: str, container: str, info: dict[str, Any], origin: Origin | None = None,
           mounts: bool | None = None, reference: str | None = None, built: bool = False) -> Assessment:
    """Decides which user the container's image may run as, by the rules in this module's docstring, for
    the project in directory (the current one for what a command line runs): looks at the image
    (inspection) as far as the policy needs, which then judges it (Policy.check_image).

    Returns an Assessment, of Kind.EXPLICIT if the container's user does not come from the image. Raises
    DockerError if the image cannot be inspected or its passwd or group file is too large.
    origin: where the container's user comes from, if known (Inspected.user_origin if not).
    mounts: the container reaches host files or devices; worked out from info if not given.
    reference: the image name as the command line or the service gave it (the container's if None).
    built: the image is built from a Dockerfile by the service; the config file never applies then.
    """
    inspected = inspection.inspect(ctx.docker, info, reference, built, mounts)
    match = config.section_for(ctx.runtime.settings, inspected.image.reference, inspected.digests, built)
    image_policy = ctx.policy_for(directory, match.repository)
    origin = origin or inspected.user_origin
    if image_policy.needs_user_files(origin):
        inspected = inspection.with_user_files(ctx.docker, container, inspected)
    return image_policy.check_image(inspected, origin, match)


# The default user owns nothing of the image's, and the image's HOME (root's, usually) is not its own.
def default_home(user: tuple[int, int], home: str) -> str:
    """Returns the HOME for a default user (uid, gid) that replaces an image's root user, or "" for none.

    home: the configured default_home. Root keeps its own.
    """
    return "" if 0 in user else home


def env_value(env: Sequence[str] | None, name: str) -> str | None:
    """Returns the value the last `name=` entry of an `Env` list of `NAME=value` strings sets, or None."""
    for entry in reversed(env or []):
        key, equals, value = entry.partition("=")
        if equals and key == name:
            return value
    return None


def runs_as(assessment: Assessment, local: hostusers.HostAccounts) -> str:
    """Describes what an accepted image (Kind.IMAGE or Kind.CONFIGURED) runs as; local: HostAccounts."""
    if assessment.kind is Kind.CONFIGURED:
        return f"runs as {ids.format_user(assessment.pinned_user)}, the user the config file sets for it"
    assert assessment.identity is not None, "an accepted image was looked at"
    return f"runs as {imageuser.describe(assessment.identity, local)}; accepted"


def instead_of_root(assessment: Assessment) -> str:
    """Describes what a Kind.FALLBACK assessment does instead of running as root."""
    return f"running as {ids.format_user(assessment.pinned_user)} instead of root"


def root_default_notice(ctx: Scope, directory: str) -> messages.Marked | None:
    """Returns the warning to give on every run in directory if the default user configured for it is root,
    else None.
    """
    default_user = ctx.settings_in(directory).default_user
    if 0 in default_user:
        default = ids.format_user(default_user)
        return messages.Marked(
            messages.WARN,
            f"the configured default user is {default}: images that would run as root run as root",
            "set default_user in the config file to change it")
    return None


def explain(ctx: Scope, assessment: Assessment) -> list[Finding]:
    """Returns the assessment's reasons, with how to get past them if they come from the image's user."""
    if not assessment.identity:
        return assessment.reasons
    help = f"{CHOOSE_HINT}, {config_hint(ctx, assessment.image.reference)}"
    return [Finding(r.text, r.severity, r.subject, help, r.output) for r in assessment.reasons]


def config_hint(ctx: Scope, image: str) -> str:
    """Returns the hint how the config file can give image a user, for an image pulled from a registry."""
    return f"or, for an image pulled from a registry, {images.section_hint(image, ctx.runtime.config_file)}"
