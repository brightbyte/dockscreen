"""This module provides functions for finding the mounts of a container or a compose service, and for telling
which of them reach files on this host.

A container's user decides its access to host files only where the container reaches them: through bind
mounts, devices, the volumes of another container, and, for compose, secrets and configs, which are
bind-mounted files. Named volumes live in docker's own directory, and tmpfs lives in memory, so the user id
means nothing to the host there. The exception is a named volume whose local driver options mount a device
or a host path; compose shows those options in the volume's `driver_opts`. Docker inspect does not say how
a container's named volumes were made.
"""

from collections.abc import Mapping
from typing import Any, NamedTuple

# Mount options that make a local volume a bind mount of whatever its device names.
BIND_FLAGS = frozenset({"bind", "rbind"})


class Mount(NamedTuple):
    """Value object for a filesystem attached to a container. It holds its type, its source and its
    target.

    Attributes:
    - kind: its type: bind, volume, tmpfs or image
    - source: where it comes from: a host path, a volume or an image
    - target: where it is mounted in the container
    """
    kind: str
    source: str
    target: str


def mount_flags(opts: Mapping[str, Any]) -> set[str]:
    """Returns the comma-separated mount options in the `o`, lower case.

    Parameters:
    - opts: a volume's driver_opts
    """
    return {flag.strip().lower() for flag in str(opts.get("o", "")).split(",")}


def volume_reaches_host(volume: Mapping[str, Any] | None) -> bool:
    """Tells whether a compose top-level volume mounts host files, which it does if its driver_opts name a
    device or mount options. A plain tmpfs does not count.
    """
    opts = (volume or {}).get("driver_opts") or {}
    # a plain tmpfs is memory, not a host path; a tmpfs with a device or the bind flag is not plain, and the
    # policy refuses it
    is_plain_tmpfs = (opts.get("type") == "tmpfs" and opts.get("device", "") in ("", "tmpfs")
                      and not mount_flags(opts) & BIND_FLAGS)
    return bool(opts.get("device") or opts.get("o")) and not is_plain_tmpfs


def service_reaches_host(service: Mapping[str, Any], volumes: Mapping[Any, Any] | None = None) -> bool:
    """Tells whether a compose service reaches host files: through bind mounts, secrets and configs, devices,
    the volumes of another container, or a named volume for which volume_reaches_host is true.

    Parameters:
    - service: the service's keys, as compose config gives them
    - volumes: the config's top-level volumes, which the service's named volumes refer to
    """
    mounts = [m for m in service.get("volumes") or [] if isinstance(m, dict)]
    has_binds = any(m.get("type") == "bind"
                    or m.get("type") == "volume" and volume_reaches_host((volumes or {}).get(m.get("source")))
                    for m in mounts)
    other_mount_keys = ("volumes_from", "devices", "secrets", "configs")
    return has_binds or any(service.get(key) for key in other_mount_keys)


def container_mounts(info: Mapping[str, Any]) -> list[Mount]:
    """Returns the mounts of a container, each one once.

    -v puts a bind mount in HostConfig.Binds, and --mount puts a mount in HostConfig.Mounts; docker inspect
    also lists all of these mounts in Mounts.

    Parameters:
    - info: what docker inspect shows of the container
    """
    host_config = info.get("HostConfig") or {}
    mounts = []
    for bind in host_config.get("Binds") or []:
        source, _, target_and_options = str(bind).partition(":")
        if source.startswith("/"):  # otherwise the source names a volume
            mounts.append(Mount("bind", source, target_and_options.partition(":")[0]))
    for mount in [*(host_config.get("Mounts") or []), *(info.get("Mounts") or [])]:
        kind = str(mount.get("Type") or "").lower()
        target = mount.get("Target") or mount.get("Destination") or ""
        mounts.append(Mount(kind, mount.get("Source") or "", target))
    mounts_by_target: dict[tuple[str, str], Mount] = {}
    for mount in mounts:
        mounts_by_target.setdefault((mount.kind, mount.source), mount)
    return list(mounts_by_target.values())


def container_reaches_host(info: Mapping[str, Any]) -> bool:
    """Tells whether a container reaches host files: bind mounts, devices, or the volumes of another
    container.

    Parameters:
    - info: what docker inspect shows of the container
    """
    host_config = info.get("HostConfig") or {}
    has_binds = any(m.kind == "bind" for m in container_mounts(info))
    return bool(has_binds or host_config.get("Devices") or host_config.get("VolumesFrom"))
