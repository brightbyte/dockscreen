"""This module defines the Container class, a view of a container as docker inspect shows it. A Container
can also give the container's requests in the terms of a compose service.

A container that `docker run` created holds its command line's requests, as the daemon parsed them.
The method Container.as_service reads the requests back into the compose service keys of the same
meaning, so that the policy for compose services can judge them, with the same wording.
"""

from collections.abc import Sequence
from typing import Any, NamedTuple, Self

from dockscreen.model import mounts
from dockscreen.model.mounts import Mount
from dockscreen.model.origin import Origin

# HostConfig fields of docker inspect, each with the compose service key that holds the same value.
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
    """View of a container as docker inspect shows it, for judging its requests in the same way as a compose
    service's (JudgedService). It holds what docker inspect shows, the directory that its bind mounts are
    judged against, and the origin of its user.

    Everything else it has comes from the command line that created it. A container that could not be
    inspected comes from the classmethod placeholder and has only its id.

    Attributes:
    - info: what docker inspect shows of it; a dict that must not be changed in place
    - directory: the directory where the command line that created it ran; None for a container that
      existed before. Docker does not record where it created a container, and its labels prove nothing,
      since an image can set them.
    - user_origin: where its user comes from
    """
    info: dict[str, Any]
    directory: str | None
    user_origin: Origin = Origin.COMMAND_LINE

    @classmethod
    def placeholder(cls, container: str, directory: str | None) -> Self:
        """Returns a placeholder for the container called container, which exists but could not be
        inspected; it was created in directory.

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
    def is_inspected(self) -> bool:
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
        """Returns the compose service keys that ask for what the container has (as_service). They include its
        user, unless the user comes from its image.
        """
        return self.as_service(includes_user=self.user_origin is not Origin.IMAGE)

    def origin_of(self, key: str) -> Origin:
        """Returns the origin of the value of key, one of the service keys in definition."""
        return self.user_origin if key == "user" else Origin.COMMAND_LINE

    def with_user_origin(self, user_origin: Origin) -> Self:
        """Returns this container with its user coming from user_origin."""
        return self._replace(user_origin=user_origin)

    def as_service(self, includes_user: bool) -> dict[str, Any]:
        """Returns the compose service keys that ask for what this container has; they include its user only
        if includes_user is set.
        """
        host_config = self.info.get("HostConfig") or {}
        service = {key: host_config[field] for field, key in SERVICE_FIELDS.items() if host_config.get(field)}
        service.setdefault("cap_drop", [])
        service.setdefault("security_opt", [])
        if host_config.get("VolumesFrom"):
            service["volumes_from"] = [f"container:{source}" for source in host_config["VolumesFrom"]]
        if mounts := self.mounts:
            service["volumes"] = [{"type": m.kind, "source": m.source, "target": m.target} for m in mounts]
        if includes_user:
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
