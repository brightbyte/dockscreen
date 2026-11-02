"""This module implements `docker compose run`, with the checks of `up` and the user the command line may
choose for the service.

The command line is trusted: a user it gives is taken as numeric `uid:gid`, or `--as NAME` and
`--as-me` are resolved to ids on this host (userargs); that service's user is then not
checked against the image.
"""

from dockscreen.cli import userargs
from dockscreen.compose import composeproject
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.findings import Report
from dockscreen.screen.scope import Scope


def gate(global_args: list[str], args: list[str], runtime: Runtime, allow_me: bool = False,
         strict: bool = False) -> int:
    """Runs `docker compose global_args run args` if the project passes the checks, and returns the exit
    status: 1 for a user on the command line that cannot be used.

    allow_me: --allow-me was given, so the caller's own ids are allowed.
    strict: --strict-screen was given, so what the command line changes in the service is judged too.
    """
    parsed = userargs.parse_compose("run", args, runtime.me, runtime.accounts)
    refusals = Scope(runtime).policy(runtime.cwd).check_user_options(parsed.users.given)
    if refusals:
        verdict.screened(Report.of(refusals))
        return 1
    return composeproject.check_and_run(global_args, "run", parsed, runtime, allow_me, strict)
