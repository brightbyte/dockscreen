"""This module implements `docker compose up` and the commands that create containers from the config as it
does (`scale`, `watch`, `alpha`).

The project is checked, its images are looked at, and compose runs the config that was checked
(projectscreening.check_and_run).
"""

from dockscreen.cli import userargs
from dockscreen.compose import projectscreening
from dockscreen.host.runtime import Runtime


def gate(global_args: list[str], sub: str, args: list[str], runtime: Runtime, allow_me: bool = False) -> int:
    """Runs `docker compose global_args sub args` if the project passes the checks, and returns the exit
    status; sub is `up` or one of its kin.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - sub: `up` or one of its kin
    - args: the subcommand's arguments
    - runtime: the Runtime of the command
    - allow_me: --allow-me was given, so the caller's own ids are allowed
    """
    return projectscreening.check_and_run(global_args, sub, userargs.Parsed.unread(args, runtime), runtime,
                                        allow_me)
