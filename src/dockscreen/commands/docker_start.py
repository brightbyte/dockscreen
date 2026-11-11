"""This module implements `docker start` and `docker restart`, with the same check as `run`, on containers
that already exist.

An existing container cannot be rewritten, so one whose user dockscreen would replace (by the default
user or a configured one) is refused like one whose user is not accepted, unless it already runs as
that user.

Docker does not record where a container was created, and its labels, which its image can set, prove
nothing. So it is judged without a directory: no project section of the config file applies, and only
the configured mount_dirs allow bind mounts.
"""


from dockscreen.commands import helptext
from dockscreen.host.docker import is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.policy.finding import Reportable
from dockscreen.policy.report import Report
from dockscreen.screen import containerscreening
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline

# Options of `docker start` and `restart` that take a value.
VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker start` or `restart` if every container it names passes check; returns 1 if one does not,
    otherwise docker replaces this process.

    Parameters:
    - parent_cli: the docker command line, with `start` or `restart` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd in ("start", "restart")
    if not Report.of(check(parent_cli, runtime)).show_screening():
        return 1
    runtime.docker.exec(parent_cli.argv)


def check(cli: commandline.CommandLine, runtime: Runtime) -> list[Reportable]:
    """Returns the refusals that forbid starting the containers that the `docker start` (or `restart`)
    command line cli names.

    Each container is judged as containerscreening.check_existing judges it, and a remote daemon is refused.

    Parameters:
    - cli: the docker command line, with `start` or `restart` as its command. With --strict-screen, what
      the command line that created a container asked for is judged as a project's would be, and refused
      (Policy.check_container)
    - runtime: the Runtime of the command
    """
    screener = Screener(runtime, own_ids_hint="")  # the image's user is set in the config file, see the hint
    if is_remote(cli.lead_args, runtime.docker):
        return [*screener.policy(None).check_daemon(True)]
    problems: list[Reportable] = []
    for ref in commandline.positionals(cli.args, VALUE_LONG, VALUE_SHORT):
        problems += containerscreening.check_existing(screener, ref, cli.strict)
    return problems


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it: start or restart
    """
    if name == "restart":
        return helptext.HelpTopic(
            "dockscreen restart [OPTIONS] CONTAINER [CONTAINER...]",
            "Restart containers, denied if they would fail the check of run",
            ("As for start.", helptext.VERDICT),
            aliases=("dockscreen container restart", "dockscreen restart"))
    assert name == "start"
    return helptext.HelpTopic(
        "dockscreen start [OPTIONS] CONTAINER [CONTAINER...]",
        "Start containers, denied if they would fail the check of run",
        (("An existing container cannot be changed, so one whose image's user dockscreen would replace or "
          "deny is denied."), helptext.VERDICT),
        aliases=("dockscreen container start", "dockscreen start"))
