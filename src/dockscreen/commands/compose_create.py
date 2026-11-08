"""This module implements `docker compose create`, with the checks of `up`, for containers that are created
and not started.

The project is checked, its images are looked at, and compose runs the config that was checked
(projectscreening.check_and_run).
"""

from dockscreen.cli import userargs
from dockscreen.commands import helptext
from dockscreen.compose import projectscreening
from dockscreen.host.runtime import Runtime
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose create` if the project passes the checks, and returns the exit status.

    Parameters:
    - parent_cli: the compose command line, with `create` as its command; its lead_args are the compose
      options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "create"
    parsed = userargs.UserArgs.unread(list(parent_cli.args), runtime)
    return projectscreening.check_and_run(list(parent_cli.lead_args), "create", parsed, runtime,
                                          parent_cli.allow_me)


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "create"
    return helptext.HelpTopic("dockscreen compose create [OPTIONS] [SERVICE...]",
                              "Create containers, after the project passes the audit",
                              helptext.SCREENED_COMPOSE)
