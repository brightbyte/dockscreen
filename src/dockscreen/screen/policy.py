"""This module defines the Policy class, for checking a compose project, a container, a build or an image
against the rules of the security policy, with the settings they apply with.

The rules are grouped by what they judge (screen.rules): the keys of a service (rules.servicerules), what
a project has besides its services (rules.projectrules), builds (rules.buildrules), and the users
containers run as (rules.userrules): a service's, an image's and the ones a command line gives. Policy has
them all, and checks whole targets with them: a project (check_project), a container read back into compose
service keys (check_container), and a project's builds (check_project_build).

The policy is an allowlist and fails closed: a key that is not listed is refused, so a Compose feature
added tomorrow is denied until someone has reviewed it. Every structure that can carry unlisted keys
(service, mount, build, volume, network, secret, deploy, develop, hooks) has its own list. Keys beginning
with `x-` are extension fields that Compose itself ignores; they pass everywhere except in `build` (see
BuildRules._check_build).

A Policy holds the settings the rules apply with, such as what the id rules, which decide which uids and
gids a project may choose, judge by (userrules.IdFacts); what is known about the thing judged belongs to it,
not to the policy, down to the directory its paths are judged against. Every rule is a method of Policy,
whether it reads the settings or not. The checks of a whole target turn the problems of each rule into
findings (finding.Finding), or into notices (notice.Notice) for a trusted value, about the service, volume
or network they concern. Nothing here touches docker, only the filesystem for realpath resolution.
"""

import dataclasses
from collections.abc import Mapping
from types import MappingProxyType
from typing import Self

from dockscreen.host import config as configuration
from dockscreen.model.container import Container
from dockscreen.model.image import Inspected, Unseen
from dockscreen.model.origin import TRUSTED, Origin
from dockscreen.model.project import Project
from dockscreen.screen import finding
from dockscreen.screen.finding import Finding, Reportable
from dockscreen.screen.rules import userrules
from dockscreen.screen.rules.base import JudgedService, unknown_keys
from dockscreen.screen.rules.buildrules import BuildRules
from dockscreen.screen.rules.projectrules import TOP_LEVEL_KEYS, ProjectRules
from dockscreen.screen.rules.servicerules import (
    HARMLESS_SERVICE_KEYS,
    REQUIRED_SERVICE_KEYS,
    SERVICE_CHECKS,
    ServiceRules,
)
from dockscreen.screen.rules.userrules import UserRules, image_problem
from dockscreen.screen.userdecision import UserDecision


@dataclasses.dataclass(frozen=True)
class Policy(ServiceRules, ProjectRules, BuildRules, UserRules):
    """Service object for checking a compose project, a container, a build or an image against the rules of
    the security policy, with the settings they apply with, as the config file sets them for one directory and
    image. It holds those settings, the origins it trusts, and the policy of each service of a project.

    The rules come from the mixins in screen.rules. Instances come from Screener.policy and
    Screener.project_policy; with_trust and the other with_* methods give copies.

    Attributes:
    - ids: what the id rules judge by (userrules.IdFacts)
    - trust: the origins whose values are taken as given: what the policy refuses in them is pointed out
      instead (with_trust)
    - config_file: the caller's config file, named in hints on what it can allow; None for no hints
    - section: which image section of the config file applies to the image this policy is for, and why the
      one for its repository does not (config.section_for); NO_SECTION for a policy not for an image
    - nobody_range: the inclusive (low, high) range of ids any project or image may choose
    - default_user: the (uid, gid) that runs instead of an image that would run as root
    - default_home: the HOME the default user gets (default_home)
    - default_origin: where the default user comes from: the config file if it sets one, else dockscreen
    """
    ids: userrules.IdFacts
    extra_dirs: tuple = ()  # mount_dirs from the config file
    trust: frozenset[Origin] = TRUSTED
    config_file: str | None = None
    security_opts: tuple = ()  # allowed besides no-new-privileges (security_opts in the config file)
    # The user the config file sets for this service (its image's or project's, or the top level's):
    # its uid and gid are allowed ids for the service too, whoever names them.
    configured_user: tuple | None = None
    nobody_range: tuple[int, int] = configuration.Config().nobody_range
    default_user: tuple[int, int] = configuration.Config().default_user
    default_home: str = configuration.Config().default_home
    default_origin: Origin = Origin.DOCKSCREEN
    section: configuration.SectionMatch = configuration.NO_SECTION
    # The policy for each service of the project this one is for, with the settings of its image section
    # if one applies, by service name; a service that is not in it gets this one.
    per_service: Mapping[str, "Policy"] = MappingProxyType({})

    @classmethod
    def for_settings(cls, settings: configuration.Config, ids: userrules.IdFacts,
                     config_file: str | None = None) -> Self:
        """Returns the policy with these settings (config.effective).

        Parameters:
        - settings: the settings of the config file that apply (config.effective)
        - ids: what the id rules judge by besides the settings: the caller, with allow_me, and this host
        - config_file: named in hints, as in Policy
        """
        return cls(ids, settings.mount_dirs, config_file=config_file, nobody_range=settings.nobody_range,
                   security_opts=settings.security_opts, configured_user=settings.user,
                   default_user=settings.default_user, default_home=settings.default_home,
                   default_origin=_origin_of(settings, "default_user"))

    def for_service(self, name: str) -> "Policy":
        """Returns the policy to check the service called name with: per_service's for it, with this one's
        trust, else this one.
        """
        found = self.per_service.get(name)
        return found.with_trust(self.trust) if found else self

    def with_section(self, section: configuration.SectionMatch) -> Self:
        """Returns this policy for an image that section says which image section applies to."""
        return dataclasses.replace(self, section=section)

    def with_trust(self, trust: frozenset[Origin]) -> Self:
        """Returns this policy with trust as the origins whose values are taken as given."""
        return dataclasses.replace(self, trust=trust)

    def with_per_service(self, per_service: Mapping[str, "Policy"]) -> Self:
        """Returns this policy with per_service as the policy of each service (for_service)."""
        return dataclasses.replace(self, per_service=MappingProxyType(dict(per_service)))

    def check_project(self, project: Project) -> list[Reportable]:
        """Checks a compose project's definition and where it is; returns what it finds, each about what it
        concerns.

        Empty if it passes. Each service is checked with its own policy (for_service). What needs docker to
        be known is checked on its own: the daemon (check_daemon), the containers that have the project's
        name (check_project_name), and the images (check_images).
        """
        config, name = project.definition, project.name
        top_level = [*unknown_keys(config, TOP_LEVEL_KEYS, "top-level key"),
                     *self._check_service_names(config)]
        problems: list[Reportable] = finding.refusals(top_level)
        if not name:  # volumes and networks are scoped to the project by its name
            problems += finding.refusals(["config has no project name"])
        for service in project.services:
            found = self.for_service(service.name).check_service(service)
            problems += finding.about(found, f"service {service.name}")
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
                build = self._check_build(service.definition["build"], service)
                problems += finding.refusals(build, f"service {service.name}")
        # build secrets refer to these
        return problems + self._check_file_sources(project.definition, project.directory)

    def check_service(self, service: JudgedService) -> list[Reportable]:
        """Checks one service; returns what it finds, empty if there is nothing.

        A problem is refused, or a warning if its value comes from an origin that this policy trusts
        (finding.judged). A user from the image is left to the image decision.
        """
        keys = service.definition
        found: list[Reportable] = []
        for key in keys:
            unknown = unknown_keys({key: keys[key]}, HARMLESS_SERVICE_KEYS | SERVICE_CHECKS.keys(), "key")
            found += finding.judged(unknown, service.origin_of(key), self.trust)
        for key, check in SERVICE_CHECKS.items():
            origin = service.origin_of(key)
            if key == "user" and origin is Origin.IMAGE:
                continue
            if key in REQUIRED_SERVICE_KEYS or key in keys:
                found += finding.judged(check(self, keys.get(key), service), origin, self.trust)
        return found

    def check_container(self, container: Container) -> list[Reportable]:
        """Checks what a container asks for as check_service would check a service that asked for the same
        (Container.definition); returns what it finds.

        Its keys come from the command line that created it, judged with the current directory as the
        project's; its user from where container.user_origin says.
        """
        return self.check_service(container)

    def check_images(self, inspected: Mapping[str, Inspected | Unseen]) -> list[Finding]:
        """Checks the images that decide the users of a project's services, as they were looked at; returns
        one finding per service that must not run (image_problem).

        Parameters:
        - inspected: by service, what was seen of the images (Inspected, or Unseen)
        """
        return [image_problem(name, decision, self.config_file)
                for name, decision in self.assess_images(inspected).items() if decision.refused]

    def assess_images(self, inspected: Mapping[str, Inspected | Unseen]) -> dict[str, UserDecision]:
        """Decides the user of each service of a project whose image decides it, from its image as it was
        looked at, with the policy for that service (for_service); returns the UserDecisions by service.

        Parameters:
        - inspected: by service, what was seen of the images (Inspected, or Unseen)
        """
        found = {}
        for name, image in inspected.items():
            if isinstance(image, Unseen):
                found[name] = UserDecision.failure(image.image, image.reason)
            else:
                service_policy = self.for_service(name)
                found[name] = service_policy.check_image(image, Origin.IMAGE)
        return found


def _origin_of(settings: configuration.Config, key: str) -> Origin:
    """Returns where the setting called key comes from: the config file if one sets it, else dockscreen."""
    return Origin.CONFIG if key in settings.configured else Origin.DOCKSCREEN
