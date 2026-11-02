"""This module defines a compose project as screening sees it, and the services in it.

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
from dockscreen.model.location import Location
from dockscreen.model.origin import Origin


class Project(NamedTuple):
    """Compose project: its definition, where it is, whether its daemon may not be this host's (remote), the
    directories that the containers with its name say they were made from ("" for one that does not say;
    made_from), where the values in its definition come from where that is not the project (origins, by
    service and key), and what was found of its services' images.

    The images are those an image section of the config file could apply to, as found here, with where
    they were pulled from (found_images, by service), and those of the services whose image decides their
    user, as looked at (inspected, by service). remote, made_from and the images are None until they are
    looked at.
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
    """Service of a compose project, called name: its keys as the project's definition gives them, and what
    follows from them.
    """
    project: Project
    name: str

    @property
    def definition(self) -> dict[str, Any]:
        """Returns its keys, as the project's definition gives them."""
        return (self.project.definition.get("services") or {}).get(self.name) or {}

    @property
    def reaches_host(self) -> bool:
        """Tells whether it reaches host files (mounts.service_reaches_host)."""
        return mounts.service_reaches_host(self.definition, self.project.volumes)

    def origin_of(self, key: str) -> Origin:
        """Returns where the value of key comes from: the project, unless dockscreen set it."""
        return (self.project.origins.get(self.name) or {}).get(key, Origin.PROJECT)
