"""This module implements `docker create`, which adds the hardening defaults, replaces the users of --as and
--as-me by ids, and checks nothing.

The container is checked when it is started (docker_start).
"""

from collections.abc import Sequence

from dockscreen.cli import runargs
from dockscreen.commands import helptext
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.findings import Report
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, messages


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker create` with the defaults added and --as and --as-me replaced by ids; returns 1 for a user
    that cannot be used, otherwise docker replaces this process.

    Parameters:
    - parent_cli: the docker command line, with `create` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "create"
    args = parent_cli.args
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:  # docker will report what is wrong with them
        resolved: Sequence[str] = args
    else:
        refusals = Screener(runtime).policy(runtime.cwd).check_user_options(parsed.users.given)
        if refusals:
            return verdict.report(Report.of(refusals))
        for message in parsed.users.notices:
            messages.notice(message)
        resolved = parsed.create_args
    messages.notice(runargs.defaults_notice())
    runtime.docker.exec([*parent_cli.lead_args, parent_cli.cmd, *runargs.DEFAULTS, *resolved])


def help(name: str) -> helptext.Topic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "create"
    return helptext.Topic(
        "dockscreen create [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create a container, with the hardening defaults added",
        (helptext.DEFAULTS, "The container is checked when dockscreen starts it."),
        helptext.USER_OPTIONS, aliases=("dockscreen container create", "dockscreen create"))
