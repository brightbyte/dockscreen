"""This module defines the mounts of a container or a compose service, and which of them reach files on this
host.

What a container can write on the host depends on its user only where it reaches host files: bind mounts,
devices, the volumes of another container, and for compose secrets and configs, which are bind-mounted
files. Named volumes live in docker's own directory and tmpfs in memory, so the user id means nothing to
the host there; except a named volume whose local driver options mount a device or a host path, which
compose shows in the volume's `driver_opts`. A container that docker inspect shows does not say how its
named volumes were made.
"""

from collections.abc import Mapping
from typing import Any, NamedTuple

# Mount options that make a local volume a bind mount of whatever its device names.
BIND_FLAGS = frozenset({"bind", "rbind"})


class Mount(NamedTuple):
    """Filesystem attached to a container: its type (bind, volume, tmpfs, image), where it comes from and
    where it is mounted.
    """
    kind: str
    source: str
    target: str


def mount_flags(opts: Mapping[str, Any]) -> set[str]:
    """Returns the comma-separated mount options in the `o` of a volume's driver_opts, lower case."""
    return {flag.strip().lower() for flag in str(opts.get("o", "")).split(",")}


def volume_reaches_host(volume: Mapping[str, Any] | None) -> bool:
    """Tells whether a compose top-level volume mounts host files: its driver_opts name a device or mount
    options. A plain tmpfs does not count.
    """
    opts = (volume or {}).get("driver_opts") or {}
    plain_tmpfs = (opts.get("type") == "tmpfs" and opts.get("device", "") in ("", "tmpfs")
                   and not mount_flags(opts) & BIND_FLAGS)
    return bool(opts.get("device") or opts.get("o")) and not plain_tmpfs


def service_reaches_host(service: Mapping[str, Any], volumes: Mapping[Any, Any] | None = None) -> bool:
    """Tells whether a compose service reaches host files: bind mounts, secrets and configs, devices, the
    volumes of another container, or a named volume that volume_reaches_host.

    volumes: the config's top-level volumes, which the service's named volumes refer to.
    """
    mounts = [m for m in service.get("volumes") or [] if isinstance(m, dict)]
    binds = any(m.get("type") == "bind"
                or m.get("type") == "volume" and volume_reaches_host((volumes or {}).get(m.get("source")))
                for m in mounts)
    others = ("volumes_from", "devices", "secrets", "configs")
    return binds or any(service.get(key) for key in others)


def container_mounts(info: Mapping[str, Any]) -> list[Mount]:
    """Returns the mounts of a container as docker inspect shows it (info), each one once.

    -v puts a bind mount in HostConfig.Binds, --mount in HostConfig.Mounts; inspect also lists them all in
    Mounts.
    """
    host = info.get("HostConfig") or {}
    found = []
    for bind in host.get("Binds") or []:
        source, _, rest = str(bind).partition(":")
        if source.startswith("/"):  # otherwise the source names a volume
            found.append(Mount("bind", source, rest.partition(":")[0]))
    for mount in [*(host.get("Mounts") or []), *(info.get("Mounts") or [])]:
        kind = str(mount.get("Type") or "").lower()
        target = mount.get("Target") or mount.get("Destination") or ""
        found.append(Mount(kind, mount.get("Source") or "", target))
    unique: dict[tuple[str, str], Mount] = {}
    for mount in found:
        unique.setdefault((mount.kind, mount.source), mount)
    return list(unique.values())


def container_reaches_host(info: Mapping[str, Any]) -> bool:
    """Tells whether a container, as docker inspect shows it (info), reaches host files: bind mounts,
    devices, or the volumes of another container.
    """
    host = info.get("HostConfig") or {}
    binds = any(m.kind == "bind" for m in container_mounts(info))
    return bool(binds or host.get("Devices") or host.get("VolumesFrom"))
