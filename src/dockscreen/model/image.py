"""This module defines classes for representing an image as screening knows it before and after looking at it,
and functions for reading an image reference as docker does.

An image is asked for by a name (`mariadb:11`, or `<project>-<service>` for one a compose service builds).
Once it is there, the name stands for an image id, which is what dockscreen pins, so that a tag moved in
between does not change what runs.

The user an image runs as is looked at through a container created from it and never started
(Inspected): docker shows the user it would run, and the image's passwd and group files can be read from
it, which decide what that user's ids are (UserIdentity).

A reference is read as docker reads it, normalised (split_reference): `mariadb` is
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
    """Value object for an image as screening refers to it. It holds the name it is asked for by, the id that
    name stood for when it was looked at, whether a compose service builds it, and where docker says it was
    pulled from.

    Attributes:
    - reference: the name, as the command line or the service gives it
    - id: the image id; None until it was looked at, or if it could not be
    - built: whether a compose service builds it, so that no image section of the config file applies
    - digests: its RepoDigests, where docker says it was pulled from
    """
    reference: str
    id: str | None = None
    built: bool = False
    digests: tuple[str, ...] = ()


class Inspected(NamedTuple):
    """Record of what was seen of an image through a container created from it and never started, for the
    policy to decide the user from. It holds the image, its own user, the container's user, whether the
    container reaches host files, whether its HOME was chosen, and the image's passwd and group files once
    they are read.

    Instances come from Screener.look.

    Attributes:
    - image: the image (Image)
    - image_user: the user the image's config sets
    - user: the user the container was created with, as given to docker
    - reaches_host: whether the container, or the service it stands for, reaches host files
    - home_chosen: whether the container's HOME differs from the image's, so the command line or an env file
      chose it; never for a compose service, whose image is looked at without the service's environment
    - passwd, group: the image's passwd and group files as the container has them, "" for a missing one; None
      until they are read (with_user_files)
    """
    image: Image
    image_user: str
    user: str
    reaches_host: bool
    home_chosen: bool = False
    passwd: str | None = None
    group: str | None = None

    @property
    def user_origin(self) -> Origin:
        """Returns where the container's user comes from, told by itself: the image if it is the image's own,
        else the command line, the only other place a container gets one from.
        """
        return Origin.IMAGE if self.user == self.image_user else Origin.COMMAND_LINE

    def with_user_files(self, passwd: str, group: str) -> Self:
        """Returns this image with the passwd and group files read from its container."""
        return self._replace(passwd=passwd, group=group)


class Unseen(NamedTuple):
    """Record of an image that could not be looked at, and why.

    Attributes:
    - image: the image (Image)
    - reason: why it could not be looked at
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
        """Tells whether it has uid 0 or gid 0, also among its supplementary groups."""
        return 0 in (self.uid, self.gid, *self.supplementary)


def split_reference(reference: str) -> tuple[str, str, str]:
    """Splits an image reference into (normalised repository, tag, digest) as docker reads it:
    `mariadb` is docker.io/library/mariadb. Tag and digest are empty if not given.

    Raises ValueError for something that is not a reference.
    """
    name, _, digest = reference.partition("@")
    tag = ""
    last_slash = name.rfind("/")
    if ":" in name[last_slash + 1:]:  # a colon before the last slash is a registry's port, not a tag
        name, _, tag = name.rpartition(":")
    first, slash, rest = name.partition("/")
    # docker's rule: the first component is a registry only if it looks like a host
    if slash and ("." in first or ":" in first or first == "localhost"):
        domain, path = first, rest
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
    """Returns the normalised repository of a reference, or None if it is not one."""
    try:
        return split_reference(reference)[0]
    except ValueError:
        return None


def _shown(repository: str) -> str:
    """Returns a normalised repository as people write it: `mariadb` for docker.io/library/mariadb."""
    for prefix in (f"{DEFAULT_DOMAIN}/library/", f"{DEFAULT_DOMAIN}/"):
        if repository.startswith(prefix):
            return repository[len(prefix):]
    return repository


def section_hint(reference: str, config_file: str, built: bool = False) -> str | None:
    """Returns how config_file could give this image a user, or None for a built image or a reference
    that is not one.

    Parameters:
    - reference: the image name
    - config_file: the config file to name
    - built: a compose service builds the image
    """
    name = repository(reference)
    if built or not name:
        return None
    return f"set user under [images.\"{_shown(name)}\"] in {config_file}"
