"""This module defines an image as screening knows it before and after looking at it.

An image is asked for by a name (`mariadb:11`, or `<project>-<service>` for one a compose service builds).
Once it is there, the name stands for an image id, which is what dockscreen pins, so that a tag moved in
between does not change what runs.

The user an image runs as is looked at through a container created from it and never started
(Inspected): docker shows the user it would run, and the image's passwd and group files can be read from
it, which decide what that user's ids are.
"""

from typing import NamedTuple, Self

from dockscreen.model.origin import Origin


class Image(NamedTuple):
    """Image a container is made from: the name it is asked for by, the id that name stood for when it was
    looked at, and whether a compose service builds it, so that no image section of the config file applies.
    """
    reference: str
    id: str | None = None  # None until it was looked at, or if it could not be
    built: bool = False


class Inspected(NamedTuple):
    """Image as dockscreen looked at it, through a container created from it: the image, where docker says
    it was pulled from (digests), the image's own user (image_user), the user the container was created
    with, whether the container reaches host files, and the image's passwd and group files as the
    container has them ("" for a missing one), None until they are read.
    """
    image: Image
    digests: tuple[str, ...]
    image_user: str
    user: str
    reaches_host: bool
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
