"""This module reads what screening needs to know about an image through a container created from it,
without judging any of it (model.image.Inspected).
"""

from typing import Any

from dockscreen.host.dockerclient import Docker
from dockscreen.model.container import Container
from dockscreen.model.image import Image, Inspected


def inspect(docker: Docker, info: dict[str, Any], reference: str | None = None, built: bool = False,
            reaches_host: bool | None = None) -> Inspected:
    """Returns the image of the container that docker inspect shows as info, as docker inspect shows the
    image, without its passwd and group files.

    reference: the image name as the command line or the service gave it (the container's if None).
    built: a compose service builds the image. reaches_host: the container, or the service it stands for,
    reaches host files; worked out from info if None. Raises DockerError if the image cannot be inspected.
    """
    image = Image(reference or info["Config"].get("Image") or "", info["Image"], built)
    inspected = docker.inspect_image(info["Image"])
    if reaches_host is None:
        reaches_host = Container(info).reaches_host
    return Inspected(image, tuple(inspected.get("RepoDigests") or ()), inspected["Config"].get("User") or "",
                     info["Config"].get("User") or "", reaches_host)


def with_user_files(docker: Docker, container: str, inspected: Inspected) -> Inspected:
    """Returns inspected with the passwd and group files read from container; a missing file has no names
    in it, for docker as for us.

    Raises DockerError if a file cannot be read or is too large.
    """
    passwd = docker.read_file(container, "/etc/passwd") or ""
    group = docker.read_file(container, "/etc/group") or ""
    return inspected.with_user_files(passwd, group)
