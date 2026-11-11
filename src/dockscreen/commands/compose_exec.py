"""This module implements `docker compose exec`, which replaces the users of --as and --as-me by ids and
checks nothing.

The command line is trusted, and the service's container was checked when it was created.
"""

from dockscreen.commands import helptext
from dockscreen.compose import userargs, userscreening
from dockscreen.host.runtime import Runtime
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose exec` with --as and --as-me replaced by ids; returns 1 for a user that cannot be
    used, otherwise docker replaces this process.

    Parameters:
    - parent_cli: the compose command line, with `exec` as its command; its lead_args are the compose
      options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "exec"
    value_flags = userargs.COMPOSE_VALUE_FLAGS["exec"]
    resolved = userscreening.resolve_user_args(list(parent_cli.args), value_flags, runtime)
    if resolved is None:
        return 1
    runtime.docker.exec(["compose", *parent_cli.lead_args, "exec", *resolved])


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "exec"
    return helptext.HelpTopic("dockscreen compose exec [OPTIONS] SERVICE COMMAND [ARGS...]",
                              "Run a command in a running service; --as and --as-me choose the user", (),
                              helptext.USER_OPTIONS)
