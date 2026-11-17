"""This module defines the Screener class, for getting what screening one command needs from the invoking user
and this host (the runtime): the policy for each target, and what an image is like, looked at through docker.

What the checks of one project, image or container need follows from it and from where that target is:
the settings of the config file with the project and image sections that apply (sections.effective_settings),
the id rules with those settings, and the policy (Policy) built from them. The directory is the
target's: a compose project's own, for what a command line runs the current one, and none for a container
that existed before, since docker does not record where it created it.
"""

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, NamedTuple

from dockscreen.host import hostusers
from dockscreen.host.docker import Docker
from dockscreen.host.runtime import Runtime
from dockscreen.model.container import env_value
from dockscreen.model.image import Image, ImageInspection
from dockscreen.model.mounts import container_reaches_host
from dockscreen.model.origin import TRUSTED_ORIGINS, Origin
from dockscreen.model.project import Project, ServiceImages
from dockscreen.model.settings import NO_SECTION, SectionMatch
from dockscreen.policy import sections
from dockscreen.policy.decisions import Decisions
from dockscreen.policy.finding import Finding
from dockscreen.policy.policy import Policy
from dockscreen.policy.report import Report
from dockscreen.policy.rules import userrules
from dockscreen.policy.rules.userrules import Resolution, UserOption
from dockscreen.policy.userdecision import UserDecision


class Screener(NamedTuple):
    """Judge of what one command runs: a factory of the policies its checks need, and a service object that
    looks at images through docker and has them judged (look, assess, decide). It holds the runtime and
    whether the invoking user's own ids are allowed and how a refusal says to allow them.

    Create one per command from its Runtime, with allow_me if the command line asks for it, and with the
    own_ids_hint of commands that allow the invoking user's ids another way than compose does.

    Attributes:
    - runtime: the Runtime of the command
    - is_me_allowed: whether --allow-me allows the invoking user's own ids
    - own_ids_hint: how the command allows them, said when they are refused (userrules.IdFacts)
    """
    runtime: Runtime
    is_me_allowed: bool = False
    own_ids_hint: str = userrules.COMPOSE_HINT

    @property
    def docker(self) -> Docker:
        """Returns the docker to pull, build, create, inspect and start with."""
        return self.runtime.docker

    @property
    def ids(self) -> userrules.IdFacts:
        """Returns the facts the id rules judge by: the invoking user's ids and whether they are allowed, and
        this host's accounts and subordinate ranges.
        """
        runtime = self.runtime
        return userrules.IdFacts(runtime.me, self.is_me_allowed, runtime.accounts, runtime.subordinate,
                                 self.own_ids_hint)

    @property
    def local_accounts(self) -> hostusers.HostAccounts:
        """Returns the accounts of this host, for naming the users an image runs as."""
        return self.runtime.accounts

    def policy(self, directory: str | None, section: SectionMatch = NO_SECTION,
               trust: frozenset[Origin] = TRUSTED_ORIGINS) -> Policy:
        """Returns the policy for the project in directory, with the image section that section says applies,
        trusting the origins in trust.

        Parameters:
        - directory: the project directory; None if no project section applies
        - section: which image section applies (SectionMatch); none by default
        - trust: the origins whose values are taken as given
        """
        settings = sections.effective_settings(self.runtime.settings, section.repository, directory)
        target_policy = Policy.for_settings(settings, self.ids, self.runtime.config_file)
        return target_policy.with_section(section).with_trust(trust)

    def check_given_users(self, given_options: Iterable[UserOption]) -> Report:
        """Returns the report of judging the users the command line gives by the policy for the current
        directory (Policy.check_user_options): it holds their refusals, if any.

        Parameters:
        - given_options: the user options the command line gives (GivenUsers.options)
        """
        return Report.of(self.policy(self.runtime.cwd).check_user_options(given_options))

    def resolve_given_users(self, given_options: Iterable[UserOption]) -> dict[UserOption, Resolution]:
        """Returns what --as and --as-me among the user options the command line gives stand for, by the
        policy for the current directory (Policy.resolve_user_options).

        Parameters:
        - given_options: the user options the command line gives (GivenUsers.options)
        """
        return self.policy(self.runtime.cwd).resolve_user_options(given_options)

    def section_for(self, image: Image) -> SectionMatch:
        """Returns which image section applies to image, by its name and where it was pulled from
        (sections.section_for).
        """
        return sections.section_for(self.runtime.settings, image.reference, image.digests, image.is_built)

    def project_policy(self, project: Project, section_images: Mapping[str, Image] | None = None) -> Policy:
        """Returns the policy for project, which gives each service the settings of its image section, if one
        applies (Policy.for_service).

        Parameters:
        - project: the project
        - section_images: the images of project's services that were found (ServiceImages.section_images),
          None before they were looked for. Before, the section is the one the image name points to; after,
          the one its image was proven to have been pulled for (section_for), and none for an image that was
          not found
        """
        directory = project.directory
        per_service = {}
        for name, service in (project.definition.get("services") or {}).items():
            service = service or {}
            if section_images is None:
                repository = sections.repository_for_name(self.runtime.settings,
                                                          str(service.get("image") or ""),
                                                          "build" in service)
                section = SectionMatch(repository, None)
            else:
                section = self.section_for(section_images[name]) if name in section_images else NO_SECTION
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
        section_images, inspections = (images.section_images, images.inspections) if images else (None, {})
        return Decisions.of(project, self.project_policy(project, section_images), self.local_accounts,
                            inspections, failures)

    def assess(self, directory: str | None, container: str, container_info: dict[str, Any],
               origin: Origin | None = None, has_mounts: bool | None = None, reference: str | None = None,
               is_built: bool = False) -> UserDecision:
        """Decides which user the container's image may run as (rules.userrules), for the project in directory
        (the current one for what a command line runs, None for a container that existed before): looks at
        the image as far as the policy needs (look), which then judges it (Policy.check_image).

        Returns a UserDecision, with the container's user's origin if it does not come from the image. Raises
        DockerError if the image cannot be inspected or its passwd or group file is too large.

        Parameters:
        - directory: the project's directory, as above
        - container, container_info: the container created from the image, and what docker inspect shows of it
        - origin: where the container's user comes from, if known (ImageInspection.user_origin if not)
        - has_mounts: the container reaches host files or devices; worked out from container_info if not given
        - reference: the image name as the command line or the service gave it (the container's if None)
        - is_built: the image is built from a Dockerfile by the service; the config file never applies then
        """
        inspection, image_policy = self.look(directory, container, container_info, origin, has_mounts,
                                             reference, is_built)
        return image_policy.check_image(inspection, origin or inspection.user_origin)

    def look(self, directory: str | None, container: str, container_info: dict[str, Any],
             origin: Origin | None = None,
             has_mounts: bool | None = None, reference: str | None = None, is_built: bool = False
             ) -> tuple[ImageInspection, Policy]:
        """Looks at the container's image as far as the policy for it needs, without judging any of it, and
        returns what was found, with that policy (the one for its image section, section_for).

        What docker inspect shows of the image comes first; the passwd and group files are read from the
        container only if the policy needs them (Policy.needs_user_files). A missing file has no names in
        it, for docker as for us. Raises DockerError if the image cannot be inspected or its passwd or
        group file is too large.

        Parameters:
        - directory, container, container_info, origin, has_mounts, reference, is_built: as assess takes them
        """
        # by the id docker created the container from: someone may have moved the name to another image since
        image_info = self.docker.inspect_image(container_info["Image"])
        image = Image(reference or container_info["Config"].get("Image") or "", container_info["Image"],
                      is_built,
                      tuple(image_info.get("RepoDigests") or ()))
        reaches_host = has_mounts if has_mounts is not None else container_reaches_host(container_info)
        # the container has the merged environment: a HOME that differs from the image's was chosen for it
        container_home = env_value(container_info["Config"].get("Env"), "HOME")
        image_home = env_value(image_info["Config"].get("Env"), "HOME")
        image_user = image_info["Config"].get("User") or ""
        container_user = container_info["Config"].get("User") or ""
        inspection = ImageInspection(image, image_user, container_user, reaches_host,
                                     container_home != image_home)
        image_policy = self.policy(directory, self.section_for(image))
        if image_policy.needs_user_files(origin or inspection.user_origin):
            passwd = self.docker.read_file(container, "/etc/passwd") or ""
            group = self.docker.read_file(container, "/etc/group") or ""
            inspection = inspection.with_user_files(passwd, group)
        return inspection, image_policy
