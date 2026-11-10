"""This module defines the Project class, a view of a compose project as screening sees it, with classes for
where it is, for the services in it, and for what was found of their images.

Every path below the project directory can be bind-mounted, so the directory must be the one compose
uses, and must not hold anything that may not be mounted (ProjectLocation).

A project's definition is what `docker compose config` resolves from all its files: every compose file,
`.env`, `include` and `extends`, with every profile active and env files not inlined. It is what compose
runs, so it is what is judged; the files themselves are not. The project also has what its definition
does not say: where it is, and where the values that dockscreen changed in its definition come from. What
docker says about it besides (its daemon, the containers with its name, its images) is not part of it.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NamedTuple, Self

from dockscreen.model import mounts
from dockscreen.model.image import Image, Inspected, Unseen
from dockscreen.model.origin import Origin


class ProjectLocation(NamedTuple):
    """Record of where a compose project is, as compose would find it, and what makes that directory unfit to
    be a project's. It holds the directory and what was found against it.

    Instances come from inspect.locate.

    Attributes:
    - directory: the project directory
    - foreign: whether it was found by walking up from the current directory into the home directory, or into
      one the caller does not own
    - redirects: the .env files on the way that set COMPOSE_FILE or COMPOSE_PATH_SEPARATOR
    - sensitive: the sensitive paths it equals or contains ($HOME, /etc, ...)
    """
    directory: str
    foreign: bool = False
    redirects: tuple[str, ...] = ()
    sensitive: tuple[str, ...] = ()


class Project(NamedTuple):
    """View of a compose project's resolved definition, for judging it. It holds the definition, where the
    project is, and where the values dockscreen set in the definition come from.

    Instances come from inspect.project; substitutions.ProjectPatch.applied_to gives one with values changed.

    Attributes:
    - definition: what `docker compose config` resolves from all the project's files; a dict that must not
      be changed in place: with_definition gives a project with another one
    - location: where it is (ProjectLocation)
    - origins: by service and key, where the values dockscreen set come from, where that is not the project
      (with_origins)
    """
    definition: dict[str, Any]
    location: ProjectLocation
    origins: Mapping[str, Mapping[str, Origin]] = MappingProxyType({})

    @property
    def name(self) -> str | None:
        """Returns the project's name, which scopes its volumes, networks and containers; None if unset."""
        return self.definition.get("name")

    @property
    def directory(self) -> str:
        """Returns the project directory, which its relative paths and bind mounts are judged against."""
        return self.location.directory

    @property
    def volumes(self) -> dict[str, Any]:
        """Returns the top-level volumes, by name."""
        return self.definition.get("volumes") or {}

    @property
    def services(self) -> list["Service"]:
        """Returns its services, in the order of the definition."""
        return [Service(self, name) for name in self.definition.get("services") or {}]

    @property
    def services_without_user(self) -> frozenset[str]:
        """Returns the names of the services that set no user, whose image's user is what docker runs."""
        return frozenset(s.name for s in self.services if not s.definition.get("user"))

    def service(self, name: str) -> "Service":
        """Returns the service called name."""
        return Service(self, name)

    def with_definition(self, definition: dict[str, Any]) -> Self:
        """Returns this project with definition as its definition."""
        return self._replace(definition=definition)

    def with_origins(self, origins: Mapping[str, Mapping[str, Origin]]) -> Self:
        """Returns this project with origins added to where the values of its services' keys come from; a
        key in both takes its origin from origins.

        Parameters:
        - origins: by service and key, where the values come from
        """
        merged = {name: dict(keys) for name, keys in self.origins.items()}
        for name, keys in origins.items():
            merged.setdefault(name, {}).update(keys)
        return self._replace(origins=MappingProxyType({n: MappingProxyType(k) for n, k in merged.items()}))


class Service(NamedTuple):
    """View of one service of a Project, for judging its keys (JudgedService). It holds the project and the
    service's name; its keys, and what follows from them, are read from the project.

    Get one from Project.service or Project.services.

    Attributes:
    - name: the name of the service
    - project: the project (Project)
    """
    project: Project
    name: str

    @property
    def definition(self) -> dict[str, Any]:
        """Returns its keys, as the project's definition gives them."""
        return (self.project.definition.get("services") or {}).get(self.name) or {}

    @property
    def directory(self) -> str:
        """Returns the directory its relative paths and bind mounts are judged against: its project's."""
        return self.project.directory

    @property
    def reaches_host(self) -> bool:
        """Tells whether it reaches host files (mounts.service_reaches_host)."""
        return mounts.service_reaches_host(self.definition, self.project.volumes)

    def origin_of(self, key: str) -> Origin:
        """Returns where the value of key comes from: the project, unless dockscreen set it."""
        return (self.project.origins.get(self.name) or {}).get(key, Origin.PROJECT)


class ServiceImages(NamedTuple):
    """Record of what was found of the images of a compose project's services once they were acquired, for
    the policy to decide on. It holds the images found, and what was seen of those that decide the services'
    users.

    Instances come from serviceinfo.prepare.

    Attributes:
    - found: by service, the images that an image section of the config file could apply to, with where they
      were pulled from
    - inspected: by service, what was seen of the images that decide the services' users (Inspected, or
      Unseen)
    """
    found: Mapping[str, Image] = MappingProxyType({})
    inspected: Mapping[str, Inspected | Unseen] = MappingProxyType({})
