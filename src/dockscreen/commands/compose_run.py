"""This module implements `docker compose run`, with the checks of `up` and the user the command line may
choose for the service.

The command line is trusted: compose gets a user it gives as numeric `uid:gid`, and dockscreen resolves
`--as NAME` and `--as-me` to ids on this host (userargs); the policy then does not check that service's
user against the image.
"""

from dockscreen.commands import helptext, projectrun
from dockscreen.host.runtime import Runtime
from dockscreen.screen import userargs, userscreening
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose run` if the project passes the checks, and returns the exit status: 1 for a user
    on the command line that cannot be used. Under --strict-screen, the policy also judges the changes the
    command line makes to the service.

    Parameters:
    - parent_cli: the compose command line, with `run` as its command; its lead_args are the compose
      options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "run"
    parsed_args = userargs.parse_compose("run", list(parent_cli.args), runtime.me, runtime.accounts)
    user_report, user_args = userscreening.screen_user_options(parsed_args, Screener(runtime))
    if user_args is None:
        user_report.show()
        return 1
    return projectrun.check_and_run(list(parent_cli.lead_args), "run", user_args, runtime,
                                    parent_cli.is_me_allowed, parent_cli.is_strict, user_report.notices)


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "run"
    return helptext.HelpTopic("dockscreen compose run [OPTIONS] SERVICE [COMMAND] [ARGS...]",
                              "Run a one-off command, after the project passes the audit",
                              helptext.SCREENED_COMPOSE, helptext.USER_OPTIONS)
