"""This module implements `docker compose exec`, which replaces the users of --as and --as-me by ids and
checks nothing.

The command line is trusted, and the service's container was checked when it was created.
"""

from dockscreen.cli import userargs
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
    resolved = userargs.resolved(list(parent_cli.args), userargs.COMPOSE_VALUE_FLAGS["exec"], runtime)
    if resolved is None:
        return 1
    runtime.docker.exec(["compose", *parent_cli.lead_args, "exec", *resolved])
