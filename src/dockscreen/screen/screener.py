"""This module defines the Screener class, for getting what screening one command needs from the caller and
this host (the runtime): the policy for each target, and what an image is like, looked at through docker.

What the checks of one project, image or container need follows from it and from where that target is:
the settings of the config file with the project and image sections that apply (config.effective), the
id rules with those settings, and the policy (Policy) built from them. The directory is the
target's: a compose project's own, for what a command line runs the current one, and none for a container
that existed before, since docker does not record where it was created.
"""

from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple, Self

from dockscreen.host import config, hostusers
from dockscreen.host.dockerclient import Docker
from dockscreen.host.runtime import Runtime
from dockscreen.model.image import Image, Inspected
from dockscreen.model.mounts import container_reaches_host
from dockscreen.model.origin import TRUSTED, Origin
from dockscreen.model.project import Project, ServiceImages
from dockscreen.screen import idrules
from dockscreen.screen.assessment import Assessment
from dockscreen.screen.decisions import Decisions
from dockscreen.screen.findings import Finding
from dockscreen.screen.policy import Policy


class Screener(NamedTuple):
    """Judge of what one command runs: a factory of the policies its checks need, and a service object that
    looks at images through docker and has them judged (look, assess, decide). It holds the runtime and
    whether the caller's own ids are allowed.

    Create one per command from its Runtime; with_allow_me gives a copy once the command line asks for it.

    Attributes:
    - runtime: the Runtime of the command
    - allow_me: whether --allow-me (or --as-me) allows the caller's own ids
    """
    runtime: Runtime
    allow_me: bool = False

    @property
    def docker(self) -> Docker:
        """Returns the docker to pull, build, create, inspect and start with."""
        return self.runtime.docker

    @property
    def ids(self) -> idrules.Rules:
        """Returns the id rules with the config file's top-level settings."""
        return idrules.Rules.for_runtime(self.runtime, self.allow_me)

    @property
    def local(self) -> hostusers.HostAccounts:
        """Returns the accounts of this host, for naming the users an image runs as."""
        return self.runtime.accounts

    def policy(self, directory: str | None, section: config.Match = config.NO_SECTION,
               trust: frozenset[Origin] = TRUSTED) -> Policy:
        """Returns the policy for the project in directory, with the image section that section says applies,
        trusting the origins in trust.

        Parameters:
        - directory: the project directory; None if no project section applies
        - section: which image section applies (config.Match); none by default
        - trust: the origins whose values are taken as given
        """
        settings = config.effective(self.runtime.settings, section.repository, directory)
        found = Policy.for_settings(settings, self.ids, self.runtime.config_file)
        return found.with_section(section).with_trust(trust)

    def section_for(self, image: Image) -> config.Match:
        """Returns which image section applies to image, by its name and where it was pulled from
        (config.section_for).
        """
        return config.section_for(self.runtime.settings, image.reference, image.digests, image.built)

    def project_policy(self, project: Project, found: Mapping[str, Image] | None = None) -> Policy:
        """Returns the policy for project, which gives each service the settings of its image section, if one
        applies (Policy.for_service).

        Parameters:
        - project: the project
        - found: the images of project's services that were found (ServiceImages.found), None before they were
          looked for. Before, the section is the one the image name points to; after, the one its image was
          proven to have been pulled for (section_for), and none for an image that was not found
        """
        directory = project.directory
        per_service = {}
        for name, service in (project.definition.get("services") or {}).items():
            service = service or {}
            if found is None:
                repository = config.name_matches(self.runtime.settings, str(service.get("image") or ""),
                                                 "build" in service)
                section = config.Match(repository, None)
            else:
                section = self.section_for(found[name]) if name in found else config.NO_SECTION
            per_service[name] = self.policy(directory, section)
        return self.policy(directory).with_per_service(per_service)

    def decide(self, project: Project, images: ServiceImages | None, failures: Sequence[Finding] = ()
               ) -> Decisions:
        """Returns what the policy for project (project_policy) decides about its services' users from what
        was found of their images, with the failures to acquire them.

        Parameters:
        - project: the project
        - images: what was found of its images; None if acquiring them failed
        - failures: the failures to acquire them
        """
        found, inspected = (images.found, images.inspected) if images else (None, {})
        return Decisions.of(project, self.project_policy(project, found), self.local, inspected, failures)

    def assess(self, directory: str | None, container: str, info: dict[str, Any],
               origin: Origin | None = None, mounts: bool | None = None, reference: str | None = None,
               built: bool = False) -> Assessment:
        """Decides which user the container's image may run as (rules.image), for the project in directory
        (the current one for what a command line runs, None for a container that existed before): looks at
        the image as far as the policy needs (look), which then judges it (Policy.check_image).

        Returns an Assessment, with the container's user's origin if it does not come from the image. Raises
        DockerError if the image cannot be inspected or its passwd or group file is too large.

        Parameters:
        - directory: the project's directory, as above
        - container, info: the container created from the image, and what docker inspect shows of it
        - origin: where the container's user comes from, if known (Inspected.user_origin if not)
        - mounts: the container reaches host files or devices; worked out from info if not given
        - reference: the image name as the command line or the service gave it (the container's if None)
        - built: the image is built from a Dockerfile by the service; the config file never applies then
        """
        inspected, image_policy = self.look(directory, container, info, origin, mounts, reference, built)
        return image_policy.check_image(inspected, origin or inspected.user_origin)

    def look(self, directory: str | None, container: str, info: dict[str, Any], origin: Origin | None = None,
             mounts: bool | None = None, reference: str | None = None, built: bool = False
             ) -> tuple[Inspected, Policy]:
        """Looks at the container's image as far as the policy for it needs, without judging any of it, and
        returns what was found, with that policy (the one for its image section, section_for).

        What docker inspect shows of the image comes first; the passwd and group files are read from the
        container only if the policy needs them (Policy.needs_user_files). A missing file has no names in
        it, for docker as for us. Raises DockerError if the image cannot be inspected or its passwd or
        group file is too large.

        Parameters:
        - directory, container, info, origin, mounts, reference, built: as assess takes them
        """
        shown = self.docker.inspect_image(info["Image"])
        image = Image(reference or info["Config"].get("Image") or "", info["Image"], built,
                      tuple(shown.get("RepoDigests") or ()))
        reaches_host = mounts if mounts is not None else container_reaches_host(info)
        inspected = Inspected(image, shown["Config"].get("User") or "", info["Config"].get("User") or "",
                              reaches_host)
        image_policy = self.policy(directory, self.section_for(image))
        if image_policy.needs_user_files(origin or inspected.user_origin):
            passwd = self.docker.read_file(container, "/etc/passwd") or ""
            group = self.docker.read_file(container, "/etc/group") or ""
            inspected = inspected.with_user_files(passwd, group)
        return inspected, image_policy

    def with_allow_me(self, allow_me: bool) -> Self:
        """Returns this screener with the caller's own ids allowed too if allow_me (--allow-me, --as-me)."""
        return self._replace(allow_me=True) if allow_me else self
