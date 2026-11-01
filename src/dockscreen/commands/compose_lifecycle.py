"""This module implements the compose commands that act on the containers a project already has (`down`,
`rm`, `stop`, `kill`, `restart`, `start`, `pause`, `unpause`), for which only the project's name is checked.

These stop, change or remove what the name stands for, so a name that containers made from another
directory already have is refused (inspect.name_conflicts). A name chosen on the command line or in the
environment is the person's choice and is not checked.
"""

from collections.abc import Sequence

from dockscreen.compose import inspect
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict


def gate(global_args: list[str], sub: str, args: list[str], runtime: Runtime) -> int:
    """Runs `docker compose global_args sub args` if the project's name is free; returns 1 if it is not,
    otherwise docker replaces this process.
    """
    reasons = check(global_args, runtime)
    if reasons:
        verdict.screened(reasons)
        return 1
    runtime.docker.exec(["compose", *global_args, sub, *args])


def check(global_args: Sequence[str], runtime: Runtime) -> list[str]:
    """Returns why the project's name may not be used: containers made from another directory have it.

    Empty for a name chosen on the command line or in the environment, and for a project that cannot be
    inspected, which is left to compose to report.
    """
    if inspect.names_project(global_args, runtime.env):
        return []
    try:
        config, directory = inspect.project(global_args, runtime)
    except inspect.ScreenError:
        return []
    if not config.get("name"):
        return []
    return inspect.name_conflicts(config["name"], directory, runtime.docker)
