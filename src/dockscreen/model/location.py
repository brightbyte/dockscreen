"""This module defines where a compose project is, and what about that place decides whether its bind mounts
can be judged against it.

Every path below the project directory can be bind-mounted, so the directory must be the one compose
uses, and must not hold anything that may not be mounted.
"""

from typing import NamedTuple


class Location(NamedTuple):
    """Directory of a compose project, as compose would find it, with what makes it unfit to be one."""
    directory: str
    # found by walking up from the current directory into the home directory or one the caller does not own
    foreign: bool = False
    redirects: tuple[str, ...] = ()  # .env files on the way that set COMPOSE_FILE or COMPOSE_PATH_SEPARATOR
    sensitive: tuple[str, ...] = ()  # the sensitive paths it equals or contains ($HOME, /etc, ...)
