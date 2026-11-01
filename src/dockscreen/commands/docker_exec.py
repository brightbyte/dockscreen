"""`docker exec`: the users of --as and --as-me replaced by ids, nothing checked.

The command line is trusted, and the container was checked when it started (docker_run, docker_start).
"""

from dockscreen import runargs, userargs
from dockscreen.host.runtime import Runtime


def gate(lead: list[str], args: list[str], runtime: Runtime) -> int:
    """Runs `lead args` (`docker exec`, with docker's options) with --as and --as-me replaced by ids;
    returns 1 for a user that cannot be used, otherwise docker replaces this process.
    """
    resolved = userargs.resolved(args, runargs.EXEC_VALUE_FLAGS, runtime)
    if resolved is None:
        return 1
    runtime.docker.exec([*lead, *resolved])
