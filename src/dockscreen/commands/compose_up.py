"""This module implements `docker compose up` and the commands that create containers from the config as it
does (`scale`, `watch`, `alpha`).

The project is checked, its images are looked at, and compose runs the config that was checked
(projectscreening.check_and_run).
"""

from dockscreen.commands import helptext
from dockscreen.compose import projectscreening, userargs
from dockscreen.host.runtime import Runtime
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose up`, or one of its kin, if the project passes the checks, and returns the exit
    status.

    Parameters:
    - parent_cli: the compose command line, with `up` or one of its kin as its command; its lead_args are the
      compose options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd is not None
    parsed = userargs.UserArgs.unread(list(parent_cli.args), runtime)
    return projectscreening.check_and_run(list(parent_cli.lead_args), parent_cli.cmd, parsed, runtime,
                                          parent_cli.allow_me)


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it: up, or watch, scale or alpha, which are screened as it is
    """
    usage, summary = {
        "up": ("[OPTIONS] [SERVICE...]", "Create and start containers, after the project passes the audit"),
        "watch": ("[OPTIONS] [SERVICE...]",
                  "Watch the build context and rebuild, after the project passes the audit"),
        "scale": ("[SERVICE=REPLICAS...]", "Scale services, after the project passes the audit"),
        "alpha": ("COMMAND", "Experimental commands, audited like up"),
    }[name]
    return helptext.HelpTopic(f"dockscreen compose {name} {usage}", summary, helptext.SCREENED_COMPOSE)
