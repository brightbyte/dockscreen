"""This module implements `docker create`, which adds the hardening defaults, replaces the users of --as and
--as-me by ids, and checks nothing.

The container is checked when it is started (docker_start).
"""

from collections.abc import Sequence

from dockscreen.commands import helptext
from dockscreen.compose import runargs, userscreening
from dockscreen.compose.screener import Screener
from dockscreen.host.runtime import Runtime
from dockscreen.screen import hardening
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
        read = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:  # docker will report what is wrong with them
        resolved: Sequence[str] = args
    else:
        users, parsed = userscreening.screened(read, Screener(runtime))
        if parsed is None:
            return users.show()
        for message in users.notices:
            messages.notice(message)
        resolved = parsed.create_args
    defaults = hardening.container_defaults()
    for notice in defaults.notices():
        messages.notice(notice)
    runtime.docker.exec([*parent_cli.lead_args, parent_cli.cmd, *defaults.applied_to(resolved)])


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "create"
    return helptext.HelpTopic(
        "dockscreen create [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create a container, with the hardening defaults added",
        (helptext.DEFAULTS, "The container is checked when dockscreen starts it."),
        helptext.USER_OPTIONS, aliases=("dockscreen container create", "dockscreen create"))
