"""This module defines the scope a command is screened in: the caller and this host (the runtime), and
whether the caller's own ids are allowed.

What the checks of one project, image or container need follows from it and from where that target is:
the settings of the config file with the project and image sections that apply (config.effective), the
id rules with those settings, and the policy (policy.Policy) built from them. The directory is the
target's: a compose project's own, or for what a command line runs, the current one.
"""

from typing import Any, NamedTuple, Self

from dockscreen.host import config, hostusers, inspection
from dockscreen.host.dockerclient import Docker
from dockscreen.host.runtime import Runtime
from dockscreen.model.image import Image, Inspected
from dockscreen.model.origin import TRUSTED, Origin
from dockscreen.model.project import Project
from dockscreen.screen import idrules, policy
from dockscreen.screen.assessment import Assessment


class Scope(NamedTuple):
    """Scope a command is screened in: the runtime, and whether --allow-me (or --as-me) allows the caller's
    own ids.
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

    def settings_in(self, directory: str) -> config.Config:
        """Returns the config file's settings for the project in directory, without any image section."""
        return config.effective(self.runtime.settings, None, directory)

    def for_image(self, repository: str | None, directory: str) -> tuple[config.Config, idrules.Rules]:
        """Returns (settings, id rules) for the project in directory, with the image section for repository
        applied (None: none applies).
        """
        settings = config.effective(self.runtime.settings, repository, directory)
        return settings, self.ids.with_settings(settings)

    def policy_for(self, directory: str, repository: str | None = None,
                   trust: frozenset[Origin] = TRUSTED) -> policy.Policy:
        """Returns the policy for a container of an image from repository (None: no image section applies)
        in the project in directory, trusting the origins in trust.
        """
        settings, _ = self.for_image(repository, directory)
        found = policy.Policy.for_settings(settings, self.ids, self.runtime.config_file)
        return found.with_trust(trust)

    def policy_here(self, repository: str | None = None, trust: frozenset[Origin] = TRUSTED) -> policy.Policy:
        """Returns the policy for what the command line runs (policy_for), in the current directory."""
        return self.policy_for(self.runtime.cwd, repository, trust)

    def image_policy(self, directory: str, image: Image) -> policy.Policy:
        """Returns the policy for a container of image in the project in directory, with the image section
        that its name and where it was pulled from show to apply (config.section_for).
        """
        match = config.section_for(self.runtime.settings, image.reference, image.digests, image.built)
        return self.policy_for(directory, match.repository).with_section(match)

    def project_policy(self, project: Project) -> policy.Policy:
        """Returns the policy for project, which gives each service the settings of its image section, if one
        applies (policy.Policy.for_service).

        Before the images were found (Project.found_images), that is the section the image name points to;
        once they were, the section its image was proven to have been pulled for (image_policy), and none
        for an image that was not found.
        """
        directory, found = project.directory, project.found_images

        def per_service(name: str, service: dict[str, Any]) -> policy.Policy:
            if found is None:
                image = str(service.get("image") or "")
                repository = config.name_matches(self.runtime.settings, image, "build" in service)
                return self.policy_for(directory, repository)
            if name in found:
                return self.image_policy(directory, found[name])
            return self.policy_for(directory)

        return self.policy_for(directory).with_per_service(per_service)

    def assess(self, directory: str, container: str, info: dict[str, Any], origin: Origin | None = None,
               mounts: bool | None = None, reference: str | None = None, built: bool = False) -> Assessment:
        """Decides which user the container's image may run as (rules.image), for the project in directory
        (the current one for what a command line runs): looks at the image as far as the policy needs
        (look), which then judges it (Policy.check_image).

        Returns an Assessment, with the container's user's origin if it does not come from the image. Raises
        DockerError if the image cannot be inspected or its passwd or group file is too large.
        container and info: the container created from the image, and what docker inspect shows of it.
        origin: where the container's user comes from, if known (Inspected.user_origin if not).
        mounts: the container reaches host files or devices; worked out from info if not given.
        reference: the image name as the command line or the service gave it (the container's if None).
        built: the image is built from a Dockerfile by the service; the config file never applies then.
        """
        inspected, image_policy = self.look(directory, container, info, origin, mounts, reference, built)
        return image_policy.check_image(inspected, origin or inspected.user_origin)

    def look(self, directory: str, container: str, info: dict[str, Any], origin: Origin | None = None,
             mounts: bool | None = None, reference: str | None = None, built: bool = False
             ) -> tuple[Inspected, policy.Policy]:
        """Looks at the container's image as far as the policy for it needs (inspection), and returns what
        was found, with that policy (image_policy); the arguments are assess's.

        Raises DockerError if the image cannot be inspected or its passwd or group file is too large.
        """
        inspected = inspection.inspect(self.docker, info, reference, built, mounts)
        image_policy = self.image_policy(directory, inspected.image)
        if image_policy.needs_user_files(origin or inspected.user_origin):
            inspected = inspection.with_user_files(self.docker, container, inspected)
        return inspected, image_policy

    def with_allow_me(self, allow_me: bool) -> Self:
        """Returns this scope with the caller's own ids allowed too if allow_me (--allow-me, --as-me)."""
        return self._replace(allow_me=True) if allow_me else self
