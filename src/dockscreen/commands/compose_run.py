"""This module implements `docker compose run`, with the checks of `up` and the user the command line may
choose for the service.

The command line is trusted: a user it gives is taken as numeric `uid:gid`, or `--as NAME` and
`--as-me` are resolved to ids on this host (userargs); that service's user is then not
checked against the image.
"""

from dockscreen.cli import userargs
from dockscreen.commands import helptext
from dockscreen.compose import projectscreening
from dockscreen.host.runtime import Runtime
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose run` if the project passes the checks, and returns the exit status: 1 for a user
    on the command line that cannot be used. Under --strict-screen, what the command line changes in the
    service is judged too.

    Parameters:
    - parent_cli: the compose command line, with `run` as its command; its lead_args are the compose
      options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "run"
    parsed = userargs.parse_compose("run", list(parent_cli.args), runtime.me, runtime.accounts)
    refused = Screener(runtime).check_given_users(parsed.users.given)
    if not refused.passed:
        refused.show()
        return 1
    return projectscreening.check_and_run(list(parent_cli.lead_args), "run", parsed, runtime,
                                          parent_cli.allow_me, parent_cli.strict)


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it
    """
    assert name == "run"
    return helptext.HelpTopic("dockscreen compose run [OPTIONS] SERVICE [COMMAND] [ARGS...]",
                              "Run a one-off command, after the project passes the audit",
                              helptext.SCREENED_COMPOSE, helptext.USER_OPTIONS)
