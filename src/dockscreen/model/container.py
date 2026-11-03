"""This module defines the Container class, a view of a container as docker inspect shows it, which can also
give what the container asks for in the terms of a compose service.

A container that `docker run` created holds what its command line asked for, parsed by the daemon. Read
back into the compose service keys of the same meaning (Container.as_service), it can be judged by the
policy for compose services, with the same wording.
"""

from collections.abc import Sequence
from typing import Any, NamedTuple, Self

from dockscreen.model import mounts
from dockscreen.model.mounts import Mount
from dockscreen.model.origin import Origin

# Inspected HostConfig fields that hold what the compose key of the same meaning holds.
SERVICE_FIELDS = {
    "Privileged": "privileged",
    "CapAdd": "cap_add",
    "CapDrop": "cap_drop",
    "SecurityOpt": "security_opt",
    "Devices": "devices",
    "DeviceCgroupRules": "device_cgroup_rules",
    "DeviceRequests": "gpus",
    "CgroupParent": "cgroup_parent",
    "Runtime": "runtime",
    "GroupAdd": "group_add",
    "PidMode": "pid",
    "IpcMode": "ipc",
    "UTSMode": "uts",
    "UsernsMode": "userns_mode",
    "CgroupnsMode": "cgroup",
    "NetworkMode": "network_mode",
}


class Container(NamedTuple):
    """View of a container as docker inspect shows it, for judging what it asks for as a compose service is
    judged (Subject). It holds what docker inspect shows, the directory its bind mounts are judged against,
    and where its user comes from.

    Everything else it has comes from the command line that created it. A container that could not be
    inspected comes from uninspected and has only its id.

    Attributes:
    - info: what docker inspect shows of it; a dict that must not be changed in place
    - directory: the directory the command line that created it ran in; None for a container that existed
      before, since docker does not record where it was created, and its labels, which an image can set, prove
      nothing
    - user_origin: where its user comes from
    """
    info: dict[str, Any]
    directory: str | None
    user_origin: Origin = Origin.COMMAND_LINE

    @classmethod
    def uninspected(cls, container: str, directory: str | None) -> Self:
        """Returns the container called container, created in directory, which exists but could not be
        inspected.

        Parameters:
        - container: its name or id
        - directory: the directory it was created in; None if not known
        """
        return cls({"Id": container}, directory)

    @property
    def id(self) -> str:
        """Returns its id, or the name it was found by if it could not be inspected."""
        return self.info["Id"]

    @property
    def inspected(self) -> bool:
        """Tells whether docker inspect showed it; if not, only its id is known."""
        return "Config" in self.info

    @property
    def user(self) -> str:
        """Returns the user it runs as, as given to docker; "" for its image's."""
        return self.info["Config"].get("User") or ""

    @property
    def mounts(self) -> list[Mount]:
        """Returns its mounts, each one once (mounts.container_mounts)."""
        return mounts.container_mounts(self.info)

    @property
    def reaches_host(self) -> bool:
        """Tells whether it reaches host files (mounts.container_reaches_host)."""
        return mounts.container_reaches_host(self.info)

    @property
    def definition(self) -> dict[str, Any]:
        """Returns the compose service keys that ask for what it has (as_service), with its user unless that
        comes from its image.
        """
        return self.as_service(with_user=self.user_origin is not Origin.IMAGE)

    def origin_of(self, key: str) -> Origin:
        """Returns where the value of the service key of definition comes from."""
        return self.user_origin if key == "user" else Origin.COMMAND_LINE

    def with_user_origin(self, user_origin: Origin) -> Self:
        """Returns this container with its user coming from user_origin."""
        return self._replace(user_origin=user_origin)

    def as_service(self, with_user: bool) -> dict[str, Any]:
        """Returns the compose service keys that ask for what this container has; its user only if
        with_user.
        """
        host = self.info.get("HostConfig") or {}
        service = {key: host[field] for field, key in SERVICE_FIELDS.items() if host.get(field)}
        service.setdefault("cap_drop", [])
        service.setdefault("security_opt", [])
        if host.get("VolumesFrom"):
            service["volumes_from"] = [f"container:{source}" for source in host["VolumesFrom"]]
        if found := self.mounts:
            service["volumes"] = [{"type": m.kind, "source": m.source, "target": m.target} for m in found]
        if with_user:
            service["user"] = self.user
        return service


def env_value(env: Sequence[str] | None, name: str) -> str | None:
    """Returns the value the last `name=` entry sets, or None.

    Parameters:
    - env: an `Env` list of `NAME=value` strings; None for none
    - name: the variable
    """
    for entry in reversed(env or []):
        key, equals, value = entry.partition("=")
        if equals and key == name:
            return value
    return None
