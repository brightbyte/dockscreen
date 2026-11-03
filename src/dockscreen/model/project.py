"""This module defines the Project class, a view of a compose project as screening sees it, with classes for
where it is and for the services in it.

Every path below the project directory can be bind-mounted, so the directory must be the one compose
uses, and must not hold anything that may not be mounted (Location).

A project's definition is what `docker compose config` resolves from all its files: every compose file,
`.env`, `include` and `extends`, with every profile active and env files not inlined. It is what compose
runs, so it is what is judged; the files themselves are not. The project also has what its definition
does not say: where it is, which daemon its containers would run on, which containers already have its
name, and where the values that dockscreen changed in its definition come from.

What is known about a project is gathered in stages, some of which ask docker; a fact that was not
looked at yet is None, and the checks of the project judge what is known.
"""

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, NamedTuple, Self

from dockscreen.model import mounts
from dockscreen.model.image import Image, Inspected, Unseen
from dockscreen.model.origin import Origin


class Location(NamedTuple):
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
    """View of a compose project's resolved definition, with what screening found out about the project
    besides, for judging it. It holds the definition, where the project is, and the facts that screening
    gathers in stages.

    Instances come from inspect.project; each stage of screening adds what it found through a with_* copy.

    Attributes:
    - definition: what `docker compose config` resolves from all the project's files; a dict that must not
      be changed in place: with_definition gives a project with another one
    - location: where it is (Location)
    - remote: whether its daemon may not be this host's; None until looked at
    - origins: by service and key, where the values dockscreen set come from, where that is not the project
      (with_origins)
    - made_from: the directories that the containers with its name say they were made from, "" for one that
      does not say; None until looked at
    - found_images: by service, the images that an image section of the config file could apply to, as found,
      with where they were pulled from; None until looked at
    - inspected: by service, what was seen of the images that decide the services' users (Inspected, or
      Unseen); None until looked at
    """
    definition: dict[str, Any]
    location: Location
    remote: bool | None = None
    origins: Mapping[str, Mapping[str, Origin]] = MappingProxyType({})
    made_from: tuple[str, ...] | None = None
    found_images: Mapping[str, Image] | None = None
    inspected: Mapping[str, Inspected | Unseen] | None = None

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

    def with_remote(self, remote: bool) -> Self:
        """Returns this project with remote telling whether its daemon may not be this host's."""
        return self._replace(remote=remote)

    def with_made_from(self, made_from: Sequence[str]) -> Self:
        """Returns this project with made_from as the directories the containers with its name were made
        from.
        """
        return self._replace(made_from=tuple(made_from))

    def with_images(self, found: Mapping[str, Image], inspected: Mapping[str, Inspected | Unseen]) -> Self:
        """Returns this project with found as its services' images that were found, and inspected as those
        of the services whose image decides their user, as looked at.
        """
        return self._replace(found_images=MappingProxyType(dict(found)),
                             inspected=MappingProxyType(dict(inspected)))

    def with_definition(self, definition: dict[str, Any]) -> Self:
        """Returns this project with definition as its definition."""
        return self._replace(definition=definition)

    def with_origins(self, origins: Mapping[str, Mapping[str, Origin]]) -> Self:
        """Returns this project with origins added to where the values of its services' keys come from; a
        key in both takes its origin from origins.
        """
        merged = {name: dict(keys) for name, keys in self.origins.items()}
        for name, keys in origins.items():
            merged.setdefault(name, {}).update(keys)
        return self._replace(origins=MappingProxyType({n: MappingProxyType(k) for n, k in merged.items()}))


class Service(NamedTuple):
    """View of one service of a Project, for judging its keys (Subject). It holds the project and the
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
