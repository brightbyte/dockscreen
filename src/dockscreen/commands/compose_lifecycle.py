"""This module implements the compose commands that act on the containers a project already has (`down`,
`rm`, `stop`, `kill`, `restart`, `start`, `pause`, `unpause`), for which only the project's name is checked.

These stop, change or remove what the name stands for, so a name that containers made from another
directory already have is refused (inspect.name_conflicts). A name chosen on the command line or in the
environment is the person's choice and is not checked.
"""

from collections.abc import Sequence

from dockscreen.host.docker import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.policy.finding import Finding
from dockscreen.policy.report import Report
from dockscreen.screen import inspect
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose down`, `rm`, `stop` or another command that uses the project's name if the name is
    free; returns 1 if it is not, otherwise docker replaces this process.

    Parameters:
    - parent_cli: the compose command line, with the subcommand as its command; its lead_args are the compose
      options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd is not None
    global_args = parent_cli.lead_args
    reasons = check(global_args, runtime)
    if reasons:
        Report.of(reasons).show_screening()
        return 1
    runtime.docker.exec(["compose", *global_args, parent_cli.cmd, *parent_cli.args])


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
    except (inspect.ProjectRefused, DockerError):
        return []
    if not project.name:
        return []
    project_policy = Screener(runtime).project_policy(project)
    return inspect.name_conflicts(project_policy, project.name, project.directory, runtime.docker)
