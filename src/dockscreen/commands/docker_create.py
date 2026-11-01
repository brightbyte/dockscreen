"""`docker create`: the hardening defaults and the users of --as and --as-me, nothing checked.

The container is checked when it is started (docker_start).
"""

from dockscreen.cli import runargs
from dockscreen.host import hostusers
from dockscreen.host.runtime import Runtime
from dockscreen.util import messages


def gate(lead: list[str], args: list[str], runtime: Runtime) -> int:
    """Runs `lead args` (`docker create`, with docker's options) with the defaults added and --as and --as-me
    replaced by ids; returns 1 for a user that cannot be used, otherwise docker replaces this process.
    """
    try:
        resolved = _create_args(args, runtime)
    except hostusers.UserError as e:
        return messages.refuse([str(e)])
    messages.notice(runargs.defaults_notice())
    runtime.docker.exec([*lead, *runargs.DEFAULTS, *resolved])


def _create_args(args: list[str], runtime: Runtime) -> list[str]:
    """Returns the arguments of `docker create` with --as and --as-me replaced by ids, and prints notices.

    Arguments that cannot be read are returned as they are: docker will report what is wrong with them.
    Raises hostusers.UserError for a user that cannot be used.
    """
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:
        return args
    for message in parsed.notices:
        messages.notice(message)
    return parsed.create_args
