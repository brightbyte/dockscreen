"""This module defines classes for representing an image as screening knows it before and after looking at it,
and functions for reading an image reference as docker does.

A service or command line asks for an image by a name: `mariadb:11`, or `<project>-<service>` for an image
that a compose service builds. Once the image is there, the name stands for an image id. dockscreen pins
that id, so that a tag moved in between does not change the image that runs.

dockscreen looks at the user that an image runs as through a container that it creates from the image and
never starts (ImageInspection). Docker shows the user that the container would run as, and dockscreen can
read the image's passwd and group files from the container. Those files decide the user's ids
(UserIdentity).

dockscreen reads a reference as docker reads it, normalised (split_reference): `mariadb` is
docker.io/library/mariadb.
"""

import re
from typing import NamedTuple, Self

from dockscreen.model.origin import Origin

DEFAULT_DOMAIN = "docker.io"
LEGACY_DOMAINS = frozenset({"index.docker.io", "registry-1.docker.io"})
# distribution/reference: a path component is lower-case alphanumerics and separators.
COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")


class Image(NamedTuple):
    """Value object for an image as screening refers to it. It holds the name that it is asked for by, the id
    that the name stood for when dockscreen looked at it, whether a compose service builds it, and where
    docker says it was pulled from.

    Attributes:
    - reference: the name, as the command line or the service gives it
    - id: the image id; None until dockscreen looked at the image, or if dockscreen could not look at it
    - is_built: whether a compose service builds it, so that no image section of the config file applies
    - digests: its RepoDigests, where docker says it was pulled from
    """
    reference: str
    id: str | None = None
    is_built: bool = False
    digests: tuple[str, ...] = ()


class ImageInspection(NamedTuple):
    """Record of the facts seen of an image, through a container created from it and never started. The
    policy decides the user from them. It holds the image, its own user, the container's user, whether the
    container reaches host files, whether its HOME was chosen, and the image's passwd and group files once
    they are read.

    Instances come from Screener.look.

    Attributes:
    - image: the image (Image)
    - image_user: the user the image's config sets
    - user: the user the container was created with, as given to docker
    - reaches_host: whether the container, or the service it stands for, reaches host files
    - is_home_chosen: whether the container's HOME differs from the image's, which means that the command
      line or an env file chose it. It is never set for a compose service, because dockscreen looks at its
      image without the service's environment.
    - passwd, group: the image's passwd and group files as the container has them; "" for a missing file,
      and None until they are read (with_user_files)
    """
    image: Image
    image_user: str
    user: str
    reaches_host: bool
    is_home_chosen: bool = False
    passwd: str | None = None
    group: str | None = None

    @property
    def user_origin(self) -> Origin:
        """Returns the origin of the container's user, judged from the container alone. That is the image if
        the user is the image's own, and the command line otherwise, since a container gets a user nowhere
        else.
        """
        return Origin.IMAGE if self.user == self.image_user else Origin.COMMAND_LINE

    def with_user_files(self, passwd: str, group: str) -> Self:
        """Returns this inspection with the passwd and group files, as read from its container."""
        return self._replace(passwd=passwd, group=group)


class UnseenImage(NamedTuple):
    """Record of an image that dockscreen could not look at, and of the reason.

    Attributes:
    - image: the image (Image)
    - reason: the reason dockscreen could not look at the image
    """
    image: Image
    reason: str


class UserIdentity(NamedTuple):
    """Value object for the set of ids a process runs as. It holds a uid, a primary gid and the supplementary
    gids.

    Attributes:
    - uid, gid: the uid and the primary gid
    - supplementary: the supplementary gids
    """
    uid: int
    gid: int
    supplementary: tuple[int, ...] = ()

    @property
    def involves_root(self) -> bool:
        """Tells whether the identity has uid 0 or gid 0, the supplementary gids included."""
        return 0 in (self.uid, self.gid, *self.supplementary)


def split_reference(reference: str) -> tuple[str, str, str]:
    """Splits an image reference into (normalised repository, tag, digest) as docker reads it:
    `mariadb` is docker.io/library/mariadb. Tag and digest are empty if not given.

    dockscreen matches image sections of the config file by the normalised repository. That way, every
    spelling that docker reads as the same repository finds the same section, and a spelling that docker
    reads as another repository (`evil.example/mariadb`, `someone/mariadb`) does not.

    Raises ValueError for something that is not a reference.
    """
    name, _, digest = reference.partition("@")
    tag = ""
    last_slash = name.rfind("/")
    if ":" in name[last_slash + 1:]:  # a colon before the last slash is a registry's port, not a tag
        name, _, tag = name.rpartition(":")
    first_part, slash, remainder = name.partition("/")
    # docker's rule: the first component is a registry only if it looks like a host
    if slash and ("." in first_part or ":" in first_part or first_part == "localhost"):
        domain, path = first_part, remainder
    else:
        domain, path = DEFAULT_DOMAIN, name
    if domain in LEGACY_DOMAINS:
        domain = DEFAULT_DOMAIN
    if domain == DEFAULT_DOMAIN and "/" not in path:
        path = "library/" + path
    if not path or not all(COMPONENT.match(part) for part in path.split("/")):
        raise ValueError(f"{reference!r} is not an image reference")
    return f"{domain}/{path}", tag, digest


def repository(reference: str) -> str | None:
    """Returns the normalised repository of reference, or None if the text is not an image reference."""
    try:
        return split_reference(reference)[0]
    except ValueError:
        return None


def _display_name(repository: str) -> str:
    """Returns a normalised repository as people write it: `mariadb` for docker.io/library/mariadb."""
    for prefix in (f"{DEFAULT_DOMAIN}/library/", f"{DEFAULT_DOMAIN}/"):
        if repository.startswith(prefix):
            return repository[len(prefix):]
    return repository


def section_hint(reference: str, config_file: str, is_built: bool = False) -> str | None:
    """Returns a hint on giving this image a user in config_file, or None for a built image or for a
    reference that docker cannot read.

    Parameters:
    - reference: the image name
    - config_file: the config file to name
    - is_built: a compose service builds the image
    """
    name = repository(reference)
    if is_built or not name:
        return None
    return f"set user under [images.\"{_display_name(name)}\"] in {config_file}"
