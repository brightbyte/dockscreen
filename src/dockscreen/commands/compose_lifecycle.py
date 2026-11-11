"""This module implements the compose commands that act on the containers a project already has (`down`,
`rm`, `stop`, `kill`, `restart`, `start`, `pause`, `unpause`), for which only the project's name is checked.

These stop, change or remove what the name stands for, so a name that containers made from another
directory already have is refused (projectscreening.check_name). A name chosen on the command line or in the
environment is the person's choice and is not checked.
"""

from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.screen import projectscreening
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
    reasons = projectscreening.check_name(global_args, runtime)
    if reasons:
        Report.of(reasons).show_screening()
        return 1
    runtime.docker.exec(["compose", *global_args, parent_cli.cmd, *parent_cli.args])
