"""This module implements `docker compose build` and `bake`, checking only what a build can reach before
compose builds the project.

Builds start no containers of the project, so only what a build can reach is checked
(policy.Policy.check_project_build): build sources inside the project, no host network, no `x-` keys that
`buildx bake` would read.
"""

from dockscreen.compose import inspect
from dockscreen.host.runtime import Runtime
from dockscreen.screen import policy


def gate(global_args: list[str], sub: str, args: list[str], runtime: Runtime) -> int:
    """Runs `docker compose global_args sub args` if the project's builds pass the checks; returns 1 if they
    do not, otherwise docker replaces this process.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - sub: `build` or `bake`
    - args: the subcommand's arguments
    - runtime: the Runtime of the command
    """
    if not inspect.passes(global_args, runtime, policy.Policy.check_project_build):
        return 1
    runtime.docker.exec(["compose", *global_args, sub, *args])
