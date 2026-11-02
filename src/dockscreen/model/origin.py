"""This module defines where the values that screening judges come from, and which of those sources are
trusted.

Screening knows a value's origin only as finely as docker shows it. `docker compose config` merges the
compose files, `.env`, env files, `include` and `extends`, so everything in it comes from the project.
A container that `docker run` created has what the command line asked for, except a user equal to its
image's own, which comes from the image.
"""

import enum


class Origin(enum.Enum):
    """Source of a value that screening judges."""
    COMMAND_LINE = "command line"  # the person typing the command
    CONFIG = "config file"         # dockscreen's config files, which only their owner or root can write
    PROJECT = "project"            # the compose project: its files, .env, env files and fragments
    IMAGE = "image"                # its USER, /etc/passwd and /etc/group
    DOCKSCREEN = "dockscreen"      # chosen by dockscreen from what it checked


# Whose values are taken as given: what the policy refuses in them is pointed out, not refused.
TRUSTED = frozenset({Origin.COMMAND_LINE, Origin.CONFIG, Origin.DOCKSCREEN})
# --strict-screen: the command line is judged like a project.
STRICT = TRUSTED - {Origin.COMMAND_LINE}
