"""`docker compose run`: the checks of `up`, with the user the command line may choose for the service.

The command line is trusted: a user it gives is taken as numeric `uid:gid`, or `--as NAME` and
`--as-me` are resolved to ids on this host (composeargs, userargs); that service's user is then not
checked against the image.
"""

from dockscreen.compose import composeargs, composeproject
from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict


def gate(global_args: list[str], args: list[str], runtime: Runtime, allow_me: bool = False) -> int:
    """Runs `docker compose global_args run args` if the project passes the checks, and returns the exit
    status: 1 for a user on the command line that cannot be used.

    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    try:
        parsed = composeargs.parse("run", args, runtime.me, runtime.accounts)
    except hostusers.UserError as e:
        verdict.screened([str(e)])
        return 1
    return composeproject.check_and_run(global_args, "run", parsed, runtime, allow_me)
