"""This module implements `docker compose create`, with the checks of `up`, for containers that are created
and not started.

The project is checked, its images are looked at, and compose runs the config that was checked
(projectscreening.check_and_run).
"""

from dockscreen.cli import userargs
from dockscreen.compose import projectscreening
from dockscreen.host.runtime import Runtime


def gate(global_args: list[str], args: list[str], runtime: Runtime, allow_me: bool = False) -> int:
    """Runs `docker compose global_args create args` if the project passes the checks, and returns the exit
    status.

    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    return projectscreening.check_and_run(global_args, "create", userargs.Parsed.unread(args, runtime),
                                        runtime, allow_me)
