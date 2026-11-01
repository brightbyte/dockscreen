"""This module implements `docker compose build` and `bake`, checking only what a build can reach before
compose builds the project.

Builds start no containers of the project, so only what a build can reach is checked
(policy.check_build_config): build sources inside the project, no host network, no `x-` keys that
`buildx bake` would read.
"""

from dockscreen.compose import inspect
from dockscreen.host.runtime import Runtime
from dockscreen.screen import policy


def gate(global_args: list[str], sub: str, args: list[str], runtime: Runtime) -> int:
    """Runs `docker compose global_args sub args` (`build` or `bake`) if the project's builds pass the
    checks; returns 1 if they do not, otherwise docker replaces this process.
    """
    if not inspect.passes(global_args, runtime, policy.check_build_config):
        return 1
    runtime.docker.exec(["compose", *global_args, sub, *args])
