"""This module implements `docker exec`, which replaces the users of --as and --as-me by ids and checks
nothing.

The command line is trusted, and the container was checked when it started (docker_run, docker_start).
"""

from dockscreen.cli import runargs, userargs
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.findings import Report
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker exec` with --as and --as-me replaced by ids; returns 1 for a user that cannot be used,
    otherwise docker replaces this process. --strict-screen is refused: exec starts a process in a running
    container at once, and there is nothing to judge before it does.

    Parameters:
    - parent_cli: the docker command line, with `exec` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "exec"
    if parent_cli.strict:
        return verdict.report(Report.refusal(commandline.STRICT_REFUSAL))

    resolved = userargs.resolved(parent_cli.args, runargs.EXEC_VALUE_FLAGS, runtime)
    if resolved is None:
        return 1
    runtime.docker.exec([*parent_cli.lead_args, "exec", *resolved])
