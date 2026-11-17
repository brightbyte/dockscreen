"""This module defines the Origin enum, for labelling where a value that screening judges comes from, and the
sets of origins that are trusted.

Screening knows a value's origin only as finely as docker shows it. `docker compose config` merges the
compose files, `.env`, env files, `include` and `extends`, so everything in it comes from the project.
A container that `docker run` created has what the command line asked for, except a user equal to its
image's own, which comes from the image.
"""

import enum


class Origin(enum.Enum):
    """Enum of the sources a value that screening judges can come from."""
    COMMAND_LINE = "command line"  # the user typing the command
    CONFIG = "config file"         # dockscreen's config files, which only their owner or root can write
    PROJECT = "project"            # the compose project: its files, .env, env files and fragments
    IMAGE = "image"                # its USER, /etc/passwd and /etc/group
    DOCKSCREEN = "dockscreen"      # chosen by dockscreen from what it checked


# The origins whose values the policy takes as given: it points out its objections to them instead of
# refusing. It checks the values dockscreen sets once more like the project's, so that a mistake in them
# stops the command.
TRUSTED_ORIGINS = frozenset({Origin.COMMAND_LINE, Origin.CONFIG})
# --strict-screen: the policy judges the command line like a project.
STRICT_ORIGINS = TRUSTED_ORIGINS - {Origin.COMMAND_LINE}
