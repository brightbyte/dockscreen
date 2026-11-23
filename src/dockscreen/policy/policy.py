"""This module defines the Policy class, for checking a compose project, a container, a build or an image
against the rules of the security policy, with the settings that the rules apply.

The package policy.rules groups the rules by subject: the keys of a service (rules.servicerules), the parts of
a project besides its services (rules.projectrules), builds (rules.buildrules), the users that containers run
as (rules.userrules), the ids that those users may have (rules.idrules), and the users that a command line
gives (rules.useroptionrules). The class Policy has all the rules, and checks whole targets with them: a
project (check_project), a container read back into compose service keys (check_container), and a project's
builds (check_project_build).

The policy is an allowlist and fails closed: it refuses a key that is not on a list, so a Compose feature that
Docker adds tomorrow stays denied until someone has reviewed it. Every structure that can carry unlisted keys
(service, mount, build, volume, network, secret, deploy, develop, hooks) has its own list. Keys beginning with
`x-` are extension fields that Compose itself ignores; they pass everywhere except in `build` (see
BuildRules._check_build).

A Policy holds the settings that the rules apply. Among them are the facts that the id rules judge by
(idrules.IdFacts); those rules decide which uids and gids a project may choose. Knowledge about the judged
thing belongs to that thing, not to the policy, down to the directory that the policy judges its paths
against. Every rule is a method of Policy, whether it reads the settings or not. The checks of a whole
target turn the problems of each rule into findings (finding.Finding), or into notices (notice.Notice) for a
trusted value. Each finding or notice is about the service, volume or network it concerns. Nothing here
touches docker; only realpath resolution reads the file system.
"""

import dataclasses
from collections.abc import Mapping
from types import MappingProxyType
from typing import Self

from dockscreen.model.container import Container
from dockscreen.model.image import ImageInspection, UnseenImage
from dockscreen.model.origin import TRUSTED_ORIGINS, Origin
from dockscreen.model.project import Project
from dockscreen.model.settings import NO_SECTION, Config, SectionMatch
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding, ReportEntry
from dockscreen.policy.rules import idrules
from dockscreen.policy.rules.base import JudgedService, unknown_key_problems
from dockscreen.policy.rules.buildrules import BuildRules
from dockscreen.policy.rules.projectrules import TOP_LEVEL_KEYS, ProjectRules
from dockscreen.policy.rules.servicerules import (
    HARMLESS_SERVICE_KEYS,
    REQUIRED_SERVICE_KEYS,
    SERVICE_CHECKS,
    ServiceRules,
)
from dockscreen.policy.rules.useroptionrules import UserOptionRules
from dockscreen.policy.rules.userrules import UserRules, image_problem
from dockscreen.policy.userdecision import UserDecision


@dataclasses.dataclass(frozen=True)
class Policy(ServiceRules, ProjectRules, BuildRules, UserRules, UserOptionRules):
    """Service object for checking a compose project, a container, a build or an image against the rules of
    the security policy. It applies the settings that the config file sets for one directory and image. It
    holds those settings, the origins it trusts, and the policy of each service of a project.

    The rules come from the mixins in policy.rules. Instances come from Screener.policy and
    Screener.project_policy. The method with_trust and the other with_* methods return copies.

    Attributes:
    - ids: what the id rules judge by (idrules.IdFacts)
    - trust: the origins whose values the policy takes as given: it points out its objections to them
      instead of refusing them (with_trust)
    - config_file: the invoking user's config file, named in hints on what it can allow; None for no hints
    - section: the image section of the config file that applies to this policy's image, or the reason that
      the section for the image's repository does not apply (sections.section_for); NO_SECTION for a policy
      that is not for an image
    - nobody_range: the inclusive (low, high) range of ids any project or image may choose
    - default_user: the (uid, gid) that runs instead of an image that would run as root
    - default_home: the HOME the default user gets (default_home)
    - default_origin: where the default user comes from: the config file if it sets one, else dockscreen
    """
    ids: idrules.IdFacts
    extra_dirs: tuple = ()  # mount_dirs from the config file
    trust: frozenset[Origin] = TRUSTED_ORIGINS
    config_file: str | None = None
    security_opts: tuple = ()  # allowed besides no-new-privileges (security_opts in the config file)
    # The user the config file sets for this service (its image's or project's, or the top level's):
    # its uid and gid are allowed ids for the service too, whoever names them.
    configured_user: tuple | None = None
    nobody_range: tuple[int, int] = Config().nobody_range
    default_user: tuple[int, int] = Config().default_user
    default_home: str = Config().default_home
    default_origin: Origin = Origin.DOCKSCREEN
    section: SectionMatch = NO_SECTION
    # By service name, the policy for each service of this policy's project, with the settings of the
    # service's image section if one applies. A service that is not in the mapping gets this policy.
    per_service: Mapping[str, "Policy"] = MappingProxyType({})

    @classmethod
    def for_settings(cls, settings: Config, ids: idrules.IdFacts,
                     config_file: str | None = None) -> Self:
        """Returns the policy with these settings (sections.effective_settings).

        Parameters:
        - settings: the settings of the config file that apply (sections.effective_settings)
        - ids: what the id rules judge by besides the settings: the invoking user, with is_me_allowed, and
          this host
        - config_file: named in hints, as in Policy
        """
        return cls(ids, settings.mount_dirs, config_file=config_file, nobody_range=settings.nobody_range,
                   security_opts=settings.security_opts, configured_user=settings.user,
                   default_user=settings.default_user, default_home=settings.default_home,
                   default_origin=_origin_of(settings, "default_user"))

    def for_service(self, name: str) -> "Policy":
        """Returns the policy for checking the service called name: its entry in per_service, with this
        policy's trust, or else this policy.
        """
        service_policy = self.per_service.get(name)
        return service_policy.with_trust(self.trust) if service_policy else self

    def with_section(self, section: SectionMatch) -> Self:
        """Returns this policy for an image, with section as the image section that applies to it."""
        return dataclasses.replace(self, section=section)

    def with_trust(self, trust: frozenset[Origin]) -> Self:
        """Returns this policy with trust as the origins whose values it takes as given."""
        return dataclasses.replace(self, trust=trust)

    def with_per_service(self, per_service: Mapping[str, "Policy"]) -> Self:
        """Returns this policy with per_service as the policy of each service (for_service)."""
        return dataclasses.replace(self, per_service=MappingProxyType(dict(per_service)))

    def check_project(self, project: Project) -> list[ReportEntry]:
        """Checks a compose project's definition and its location. Returns the findings and notices, each
        about the part of the project it concerns.

        The result is empty if the project passes. This checks each service with its own policy (for_service).
        The facts that only docker can give have checks of their own: the daemon (check_daemon), the
        containers that have the project's name (check_project_name), and the images (check_images).
        """
        config, name = project.definition, project.name
        top_level_problems = [*unknown_key_problems(config, TOP_LEVEL_KEYS, "top-level key"),
                              *self._check_service_names(config)]
        problems: list[ReportEntry] = [*finding.refusals(top_level_problems)]
        if not name:  # volumes and networks are scoped to the project by its name
            problems += finding.refusals(["config has no project name"])
        for service in project.services:
            service_findings = self.for_service(service.name).check_service(service)
            problems += finding.with_subject(service_findings, f"service {service.name}")
        for key, volume in project.volumes.items():
            volume_problems = self._check_volume(key, volume, name, project.directory)
            problems += finding.refusals(volume_problems, f"volume {key}")
        for key, network in (config.get("networks") or {}).items():
            problems += finding.refusals(self._check_network(key, network, name), f"network {key}")
        problems += self._check_file_sources(config, project.directory)
        return problems + self.check_location(project.location)

    def check_project_build(self, project: Project) -> list[Finding]:
        """Checks a compose project against the part of the policy that applies to `build`; returns the
        refusals.

        That part is what building can reach on the host: names, build sections, secrets and configs.

        Runtime hardening (user, capabilities, mounts) is irrelevant until containers run.
        """
        problems = finding.refusals(self._check_service_names(project.definition))
        for service in project.services:
            if "build" in service.definition:
                build_problems = self._check_build(service.definition["build"], service)
                problems += finding.refusals(build_problems, f"service {service.name}")
        # build secrets refer to these
        return problems + self._check_file_sources(project.definition, project.directory)

    def check_service(self, service: JudgedService) -> list[ReportEntry]:
        """Checks one service; returns the findings and notices, empty if there are none.

        A problem is refused, or a warning if its value comes from an origin that this policy trusts
        (finding.judge). This leaves a user from the image to the image decision.
        """
        definition = service.definition
        findings: list[ReportEntry] = []
        for key in definition:
            unknown_problems = unknown_key_problems({key: definition[key]},
                                                    HARMLESS_SERVICE_KEYS | SERVICE_CHECKS.keys(),
                                                    "key")
            findings += finding.judge(unknown_problems, service.origin_of(key), self.trust)
        for key, check in SERVICE_CHECKS.items():
            origin = service.origin_of(key)
            if key == "user" and origin is Origin.IMAGE:
                continue
            if key in REQUIRED_SERVICE_KEYS or key in definition:
                findings += finding.judge(check(self, definition.get(key), service), origin, self.trust)
        return findings

    def check_container(self, container: Container) -> list[ReportEntry]:
        """Checks the requests of a container, in the way that check_service checks a service with the same
        requests (Container.definition). Returns the findings and notices.

        The container's keys come from the command line that created it, and the policy judges them with the
        current directory as the project directory. Its user comes from the origin that
        container.user_origin names.
        """
        return self.check_service(container)

    def check_images(self, inspections: Mapping[str, ImageInspection | UnseenImage]) -> list[Finding]:
        """Checks the images that decide the users of a project's services, as dockscreen saw them. Returns
        one finding for each service that must not run (image_problem).

        Parameters:
        - inspections: by service, what was seen of the images (ImageInspection, or UnseenImage)
        """
        return [image_problem(name, decision, self.config_file)
                for name, decision in self.assess_images(inspections).items() if decision.is_refused]

    def assess_images(self, inspections: Mapping[str, ImageInspection | UnseenImage]
                      ) -> dict[str, UserDecision]:
        """Decides the user of each service whose image decides it. This method judges the image as dockscreen
        saw it, with the policy for that service (for_service). Returns the UserDecisions by service.

        Parameters:
        - inspections: by service, what was seen of the images (ImageInspection, or UnseenImage)
        """
        decisions = {}
        for name, inspection in inspections.items():
            if isinstance(inspection, UnseenImage):
                decisions[name] = UserDecision.failure(inspection.image, inspection.reason)
            else:
                service_policy = self.for_service(name)
                decisions[name] = service_policy.check_image(inspection, Origin.IMAGE)
        return decisions


def _origin_of(settings: Config, key: str) -> Origin:
    """Returns where the setting called key comes from: the config file if one sets it, else dockscreen."""
    return Origin.CONFIG if key in settings.configured_keys else Origin.DOCKSCREEN
