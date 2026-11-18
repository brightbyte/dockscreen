"""This module defines the Project class, a view of a compose project as screening sees it. Further classes
hold the project's location, its services, and the facts found about their images.

The project may bind mount every path below its directory, so the directory must be the one compose
uses, and it must not hold anything that may not be mounted (ProjectLocation).

A project's definition is the result of `docker compose config` on all its files: every compose file,
`.env`, `include` and `extends`, with every profile active and env files not inlined. Compose runs the
definition, so the policy judges it, and not the files themselves. The project also holds two facts that
its definition does not state: its location, and the origins of the values that dockscreen changed in the
definition. Other facts that docker gives about it (its daemon, the containers with its name, its images)
are not part of it.
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any, NamedTuple, Self

from dockscreen.model import mounts
from dockscreen.model.image import Image, ImageInspection, UnseenImage
from dockscreen.model.origin import Origin


class ProjectLocation(NamedTuple):
    """Record of a compose project's location, as compose would find it, and of anything that makes the
    directory unfit for a project. It holds the directory and the problems found with it.

    Instances come from inspect.locate.

    Attributes:
    - directory: the project directory
    - is_foreign: whether it was found by walking up from the current directory into the home directory, or
      into a directory that the user does not own
    - redirects: the .env files on the way that set COMPOSE_FILE or COMPOSE_PATH_SEPARATOR
    - sensitive_paths: the sensitive paths it equals or contains ($HOME, /etc, ...)
    """
    directory: str
    is_foreign: bool = False
    redirects: tuple[str, ...] = ()
    sensitive_paths: tuple[str, ...] = ()


class Project(NamedTuple):
    """View of a compose project's resolved definition, for judging it. It holds the definition, the project's
    location, and the origins of the values that dockscreen set in the definition.

    Instances come from inspect.project. The method projectpatch.ProjectPatch.apply_to returns a copy with
    values changed.

    Attributes:
    - definition: the result of `docker compose config` on all the project's files. It is a dict that must
      not be changed in place. The method with_definition returns a copy of the project with another
      definition.
    - location: where it is (ProjectLocation)
    - origins: by service and key, the origins of the values that dockscreen set, wherever the origin is not
      the project (with_origins)
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
        """Returns the names of the services that set no user; docker runs those as their image's user."""
        return frozenset(s.name for s in self.services if not s.definition.get("user"))

    def service(self, name: str) -> "Service":
        """Returns the service called name."""
        return Service(self, name)

    def with_definition(self, definition: dict[str, Any]) -> Self:
        """Returns this project with definition as its definition."""
        return self._replace(definition=definition)

    def with_origins(self, origins: Mapping[str, Mapping[str, Origin]]) -> Self:
        """Returns this project with origins added to the origins of its services' keys. Where a key has an
        origin in both, the origin in origins wins.

        Parameters:
        - origins: by service and key, where the values come from
        """
        merged_origins = {name: dict(keys) for name, keys in self.origins.items()}
        for name, keys in origins.items():
            merged_origins.setdefault(name, {}).update(keys)
        return self._replace(origins=MappingProxyType({n: MappingProxyType(k) for n,
                                                       k in merged_origins.items()}))


class Service(NamedTuple):
    """View of one service of a Project, for judging its keys (JudgedService). It holds the project and the
    service's name; it reads its keys, and the facts that follow from them, from the project.

    Get an instance from Project.service or Project.services.

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
    """Record of the facts found about the images of a compose project's services, once they were acquired,
    for the policy to decide on. It holds the images found, and the inspections of the images that decide
    the services' users.

    Instances come from serviceinfo.prepare.

    Attributes:
    - section_images: by service, the images that an image section of the config file could apply to, with
      where they were pulled from
    - inspections: by service, what was seen of the images that decide the services' users (ImageInspection,
      or UnseenImage)
    """
    section_images: Mapping[str, Image] = MappingProxyType({})
    inspections: Mapping[str, ImageInspection | UnseenImage] = MappingProxyType({})
