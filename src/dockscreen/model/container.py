"""This module defines a container as docker inspect shows it, and what it asks for in the terms of a compose
service.

A container that `docker run` created holds what its command line asked for, parsed by the daemon. Read
back into the compose service keys of the same meaning (Container.as_service), it can be judged by the
policy for compose services, with the same wording.
"""

from typing import Any, NamedTuple, Self

from dockscreen.model import mounts
from dockscreen.model.mounts import Mount

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
    """Container as docker inspect shows it (info): its user, its image, its mounts and its host settings."""
    info: dict[str, Any]

    @classmethod
    def uninspected(cls, container: str) -> Self:
        """Returns the container called container, which exists but could not be inspected."""
        return cls({"Id": container})

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
