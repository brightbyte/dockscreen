"""This module defines the policy's rules for the user an image runs a container as, decided from what was
seen of the image (model.image.Inspected), for `docker run` and compose alike.

The image is untrusted: its own /etc/passwd and /etc/group decide the identity docker would use (see
imageuser), and the id rules decide whether the image may have it (idrules). With no user chosen, in
this order:
- the config file names a user for the image's repository, and the image was pulled from there:
  that user, whatever it is (config.section_for, config.effective);
- the image would run as root (uid, gid or a supplementary gid of 0): the default user instead, the
  configured one or nobody, with a notice;
- otherwise the image's own user, if the id rules accept it; refused if not.

Whatever is accepted is not left for the runtime to resolve a second time: it runs as `uid:gid`, the
checked numbers, so a difference between our reading of the image's passwd and group files and the
runtime's can at worst refuse a good image, never run root.
"""

from typing import Any

from dockscreen.model.image import Identity, Inspected, section_hint
from dockscreen.model.origin import Origin
from dockscreen.screen import imageuser
from dockscreen.screen.assessment import Assessment
from dockscreen.screen.findings import Finding, Severity
from dockscreen.screen.rules.base import RuleBase


class ImageRules(RuleBase):
    """Rules for the user an image runs a container as."""

    def needs_user_files(self, origin: Origin) -> bool:
        """Tells whether check_image needs the image's passwd and group files (Inspected.passwd) for a
        container whose user comes from origin: only to judge the image's own user, when the config file
        sets none for it.
        """
        return origin is Origin.IMAGE and not self.configured_user

    def check_image(self, inspected: Inspected, origin: Origin) -> Assessment:
        """Decides which user the container that inspected looked through may run as, by the rules in this
        module's docstring; returns the Assessment.

        origin: where the container's user comes from; one that is not the image's is not judged here, and
        is the assessment's origin. The image section that applies is this policy's (section). The passwd
        and group files must have been read if needs_user_files says so.
        """
        image, match = inspected.image, self.section
        notes = (Finding(match.problem, Severity.NOTABLE),) if match.problem else ()
        found: dict[str, Any] = {"section": match}
        if origin is not Origin.IMAGE:
            return Assessment(origin, image, notes, **found)
        if self.configured_user:
            return Assessment(Origin.CONFIG, image, notes, Identity(*self.configured_user),
                              user=self.configured_user, **found)
        assert inspected.passwd is not None and inspected.group is not None, "the user files were read"
        try:
            identity = imageuser.resolve(inspected.user, inspected.passwd, inspected.group)
        except ValueError as e:
            return Assessment(Origin.IMAGE, image, (*notes, Finding(str(e))), **found)
        if identity.involves_root:
            return Assessment(self.default_origin, image, notes, identity, user=self.default_user,
                              home=self.default_home, replaces_root=True, **found)
        problems = self.ids.problems(identity.uid, identity.gid, identity.supplementary,
                                     mounts=inspected.reaches_host)
        refusals = tuple(Finding(f"the image's {p}") for p in problems)
        return Assessment(Origin.IMAGE, image, (*notes, *refusals), identity,
                          user=(identity.uid, identity.gid), **found)


def image_problem(name: str, assessment: Assessment, config_file: str | None = None) -> Finding:
    """Returns, as one finding, why the service called name must not run, for an assessment of its image
    that refused or failed.

    config_file: named in the hint for an image that is pulled, whose repository can be given a user.
    """
    image = assessment.image
    text = f"image {image.reference}: {'; '.join(r.text for r in assessment.reasons)}"
    if assessment.failed:
        return Finding(text, Severity.FAILED, f"service {name}")
    hint = section_hint(image.reference, config_file, image.built) if config_file else None
    return Finding(text, Severity.REFUSED, f"service {name}",
                   "set user: to choose one" + (f", or {hint}" if hint else ""))
