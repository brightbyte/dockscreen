"""This module defines the ids a process in a container runs as.

Docker runs a process with a uid, a primary gid and supplementary gids. Where they come from (the command
line, the config file, or the image's own passwd and group files) decides how far they are trusted; the
ids themselves are the same either way.
"""

from typing import NamedTuple


class Identity(NamedTuple):
    """Set of ids a process runs as: a uid, a primary gid and the supplementary gids."""
    uid: int
    gid: int
    supplementary: tuple[int, ...] = ()

    @property
    def involves_root(self) -> bool:
        """Tells whether it has uid 0 or gid 0, also among its supplementary groups."""
        return 0 in (self.uid, self.gid, *self.supplementary)
