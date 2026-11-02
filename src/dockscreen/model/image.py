"""This module defines an image as screening knows it before and after looking at it.

An image is asked for by a name (`mariadb:11`, or `<project>-<service>` for one a compose service builds).
Once it is there, the name stands for an image id, which is what dockscreen pins, so that a tag moved in
between does not change what runs.
"""

from typing import NamedTuple


class Image(NamedTuple):
    """Image a container is made from: the name it is asked for by, the id that name stood for when it was
    looked at, and whether a compose service builds it, so that no image section of the config file applies.
    """
    reference: str
    id: str | None = None  # None until it was looked at, or if it could not be
    built: bool = False
