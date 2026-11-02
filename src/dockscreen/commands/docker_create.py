"""This module implements `docker create`, which adds the hardening defaults, replaces the users of --as and
--as-me by ids, and checks nothing.

The container is checked when it is started (docker_start).
"""

from dockscreen.cli import runargs
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.findings import Report
from dockscreen.screen.scope import Scope
from dockscreen.util import messages


def gate(lead: list[str], args: list[str], runtime: Runtime) -> int:
    """Runs `lead args` (`docker create`, with docker's options) with the defaults added and --as and --as-me
    replaced by ids; returns 1 for a user that cannot be used, otherwise docker replaces this process.
    """
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:  # docker will report what is wrong with them
        resolved = args
    else:
        refusals = Scope(runtime).policy(runtime.cwd).check_user_options(parsed.users)
        if refusals:
            return verdict.report(Report.of(refusals))
        for message in parsed.notices:
            messages.notice(message)
        resolved = parsed.create_args
    messages.notice(runargs.defaults_notice())
    runtime.docker.exec([*lead, *runargs.DEFAULTS, *resolved])
