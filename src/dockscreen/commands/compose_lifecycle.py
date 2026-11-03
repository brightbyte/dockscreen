"""This module implements the compose commands that act on the containers a project already has (`down`,
`rm`, `stop`, `kill`, `restart`, `start`, `pause`, `unpause`), for which only the project's name is checked.

These stop, change or remove what the name stands for, so a name that containers made from another
directory already have is refused (inspect.name_conflicts). A name chosen on the command line or in the
environment is the person's choice and is not checked.
"""

from collections.abc import Sequence

from dockscreen.compose import inspect
from dockscreen.host.dockerclient import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.findings import Finding, Report
from dockscreen.screen.screener import Screener


def gate(global_args: list[str], sub: str, args: list[str], runtime: Runtime) -> int:
    """Runs `docker compose global_args sub args` if the project's name is free; returns 1 if it is not,
    otherwise docker replaces this process.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - sub: the subcommand: `down`, `rm`, `stop` or another that uses the project's name
    - args: the subcommand's arguments
    - runtime: the Runtime of the command
    """
    reasons = check(global_args, runtime)
    if reasons:
        verdict.screened(Report.of(reasons))
        return 1
    runtime.docker.exec(["compose", *global_args, sub, *args])


def check(global_args: Sequence[str], runtime: Runtime) -> list[Finding]:
    """Returns why the project's name may not be used: containers made from another directory have it.

    Empty for a name chosen on the command line or in the environment, and for a project that cannot be
    inspected, which is left to compose to report.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - runtime: the Runtime of the command
    """
    if inspect.names_project(global_args, runtime.env):
        return []
    try:
        project = inspect.project(global_args, runtime)
    except (inspect.Refused, DockerError):
        return []
    if not project.name:
        return []
    project_policy = Screener(runtime).project_policy(project)
    return inspect.name_conflicts(project_policy, project.name, project.directory, runtime.docker)
