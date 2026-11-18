"""This module implements `docker create`, which adds the hardening defaults, replaces the users of --as and
--as-me by ids, and checks nothing.

dockscreen checks the container later, when the user starts it through dockscreen (docker_start).
"""

from collections.abc import Sequence

from dockscreen.commands import helptext
from dockscreen.host.runtime import Runtime
from dockscreen.policy import hardening
from dockscreen.screen import runargs, userscreening
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, messages


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker create`, with the defaults added and --as and --as-me replaced by ids. Returns 1 for a
    user that cannot be used; otherwise docker replaces this process.

    Parameters:
    - parent_cli: the docker command line, with `create` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "create"
    args = parent_cli.args
    try:
        parsed_args = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:  # docker reports the problems with these arguments itself
        create_args: Sequence[str] = args
    else:
        user_report, run_args = userscreening.screen_user_options(parsed_args, Screener(runtime))
        if run_args is None:
            return user_report.show()
        for message in user_report.notices:
            messages.print_notice(message)
        create_args = run_args.create_args
    default_patch = hardening.container_defaults()
    for notice in default_patch.notices():
        messages.print_notice(notice)
    runtime.docker.exec([*parent_cli.lead_args, parent_cli.cmd, *default_patch.apply_to(create_args)])


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "create"
    return helptext.HelpTopic(
        "dockscreen create [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create a container, with the hardening defaults added",
        (helptext.DEFAULTS, "dockscreen checks the container when you start it with dockscreen."),
        helptext.USER_OPTIONS, aliases=("dockscreen container create", "dockscreen create"))
