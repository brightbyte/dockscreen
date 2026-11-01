"""`docker compose exec`: the users of --as and --as-me replaced by ids, nothing checked.

The command line is trusted, and the service's container was checked when it was created.
"""

from dockscreen import userargs
from dockscreen.compose import composeargs
from dockscreen.host.runtime import Runtime


def gate(global_args: list[str], args: list[str], runtime: Runtime) -> int:
    """Runs `docker compose global_args exec args` with --as and --as-me replaced by ids; returns 1 for a
    user that cannot be used, otherwise docker replaces this process.
    """
    resolved = userargs.resolved(args, composeargs.VALUE_FLAGS["exec"], runtime)
    if resolved is None:
        return 1
    runtime.docker.exec(["compose", *global_args, "exec", *resolved])
