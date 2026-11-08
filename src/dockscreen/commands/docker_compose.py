"""This module implements `docker compose` through dockscreen: it reads compose's part of the command line,
and dispatches to the compose subcommands dockscreen gates or adds, forwarding everything else.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import NoReturn

from dockscreen.commands import (
    compose_audit,
    compose_build,
    compose_create,
    compose_exec,
    compose_harden,
    compose_lifecycle,
    compose_run,
    compose_up,
    helptext,
)
from dockscreen.host import shellenv
from dockscreen.host.runtime import Runtime
from dockscreen.screen.report import Report
from dockscreen.util import commandline, messages

# dockscreen's own options before the compose subcommand; --as-me is taken out to be refused there
OWN_OPTIONS = frozenset({
    commandline.SKIP_SCREENING, commandline.ALLOW_ME, commandline.AS_ME, commandline.HELPFUL,
    commandline.VERBOSE,
})

# Global `docker compose` options that consume the following token as their value.
# Needed to tell `-f foo.yml up` (subcommand "up") from `-f up` (a value).
GLOBAL_OPTS_WITH_VALUE = frozenset({
    "--ansi",
    "--env-file",
    "-f", "--file",
    "--parallel",
    "--profile",
    "--progress",
    "--project-directory",
    "-p", "--project-name",
})

# Subcommands that create containers from the config. `alpha` is a group (older
# compose has `alpha watch`); screening it is cheap and errs on the safe side.
RUNTIME_SUBCOMMANDS = frozenset({"up", "create", "run", "watch", "scale", "alpha"})
# Subcommands that only build: they get the build-related checks, not the runtime policy.
BUILD_SUBCOMMANDS = frozenset({"build", "bake"})
SCREENED = RUNTIME_SUBCOMMANDS | BUILD_SUBCOMMANDS
# Subcommands that stop, change or remove what the project's name stands for. Only the name is checked.
NAMED_PROJECT_SUBCOMMANDS = frozenset({"down", "rm", "stop", "kill", "restart", "start", "pause", "unpause"})

# dockscreen's own subcommands, which shadow compose's of the same name; each takes the compose command line
# and the Runtime, and returns the exit status
COMMANDS: Mapping[str, Callable[[commandline.CommandLine, Runtime], int]] = MappingProxyType({
    "audit": compose_audit.audit,
    "harden": compose_harden.harden,
    "fix": compose_harden.harden,
})
ALIASES = MappingProxyType({"fix": "harden"})  # alias -> command it stands for
# the help of each command dockscreen has its own help for: of its own commands, and of the screened ones
COMMAND_HELP: Mapping[str, Callable[[str], helptext.HelpTopic]] = MappingProxyType({
    "audit": compose_audit.help,
    "harden": compose_harden.help,
})
SCREENED_HELP: Mapping[str, Callable[[str], helptext.HelpTopic]] = MappingProxyType({
    "up": compose_up.help, "watch": compose_up.help, "scale": compose_up.help, "alpha": compose_up.help,
    "create": compose_create.help,
    "run": compose_run.help,
    "build": compose_build.help, "bake": compose_build.help,
    "exec": compose_exec.help,
})


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose …`, screened, and returns the exit status unless docker replaces this process.

    Errors that stop everything (config.ConfigError, DockerNotFound) are left to docker_cli.main.

    Parameters:
    - parent_cli: the docker command line, with `compose` as its command
    - runtime: the Runtime the `docker` wrapper loaded
    """
    assert parent_cli.cmd == "compose"
    if parent_cli.lead_args:  # the compose commands are run without them
        messages.notice("docker options before `compose` are not supported")
        return 1
    cli = parent_cli.subcommand(GLOBAL_OPTS_WITH_VALUE, OWN_OPTIONS)
    if cli.skip_screening:
        commandline.banner()
        return runtime.docker.exec(cli.full_argv)
    # for `user: "${UID}:${GID}"` in compose files; only compose gets them, not this process, and not
    # with --skip-screening, which leaves compose as it is
    return ComposeCommand(cli, runtime.with_docker_env(shellenv.exported(runtime.me))).dispatch()


class ComposeCommand:
    """Command object for one `docker compose` command line, with dockscreen's own options taken out, for
    running it through dockscreen. Its dispatch method screens, helps with or forwards the command. It holds
    the command line and the runtime it runs in.

    The options before the subcommand, which select the project, are the lead_args of its command line.

    Attributes:
    - commandline: compose's part of the command line, with the subcommand as its command
    - runtime: the Runtime the command runs in
    """

    def __init__(self, cli: commandline.CommandLine, runtime: Runtime) -> None:
        self.commandline = cli
        self.runtime = runtime

    def dispatch(self) -> int:
        """Screens, helps with or forwards the command, and returns its exit status.

        Docker replaces this process if the command runs.
        """
        cli, runtime = self.commandline, self.runtime
        sub = cli.cmd
        messages.set_helpful(cli.helpful or sub == "audit")
        if cli.as_me:
            messages.notice(commandline.AS_ME_MESSAGE)
            return 2
        target = self._help_request()
        if target is not None:
            return self.show_help(target)
        if cli.strict and not supports_strict(sub):
            # refused, not ignored: a caller who asks for strict screening must not get the lenient kind
            return Report.refusal(commandline.STRICT_REFUSAL).show()
        if sub is None:
            return self._passthrough(cli.argv)
        if sub in COMMANDS:
            return COMMANDS[sub](cli, runtime)
        if sub in SCREENED:
            if sub == "run":
                return compose_run.gate(cli, runtime)
            if sub == "create":
                return compose_create.gate(cli, runtime)
            if sub in BUILD_SUBCOMMANDS:
                return compose_build.gate(cli, runtime)
            return compose_up.gate(cli, runtime)
        if sub in NAMED_PROJECT_SUBCOMMANDS:
            return compose_lifecycle.gate(cli, runtime)
        if sub == "exec":
            return compose_exec.gate(cli, runtime)
        return self._passthrough(cli.argv)

    def _help_request(self) -> str | None:
        """Determines what help the command line asks for: None for none, "" for the overview, else a command.

        `help`, `help COMMAND`, or --help or -h as the first argument after the command. Only a leading one
        counts: after `run SERVICE` the rest belongs to the service's command (`run app grep -h x`).
        """
        cli = self.commandline
        if cli.cmd is None:
            lead = cli.lead_args
            return "" if not lead or "--help" in lead or "-h" in lead else None
        if cli.cmd == "help":
            return cli.args[0] if cli.args else ""
        return cli.cmd if cli.args[:1] in (("--help",), ("-h",)) else None

    def show_help(self, target: str) -> int:
        """Prints dockscreen's help for target, then forwards to compose's own help if it has one.

        Parameters:
        - target: the subcommand to give the help of; "" for compose itself
        """
        if target == "":
            screened, own = helptext.topics(SCREENED_HELP), helptext.topics(COMMAND_HELP)
            helptext.show(lambda width: helptext.compose_overview(screened, own, width))
        elif target in COMMANDS:
            name = ALIASES.get(target, target)
            topic = COMMAND_HELP[name](name)
            helptext.show(lambda width: helptext.topic(topic, "", width))
            return 0
        elif target in SCREENED_HELP:
            topic = SCREENED_HELP[target](target)
            helptext.show(lambda width: helptext.topic(topic, "Docker Compose's own", width))
        cli = self.commandline
        argv = cli.argv
        if cli.cmd == "help":  # compose has no help command of its own
            argv = [*cli.lead_args, *([target] if target else []), "--help"]
        return self._passthrough(argv)

    def _passthrough(self, argv: Sequence[str]) -> NoReturn:
        """Replaces this process with `docker compose argv`, keeping tty, signals and exit code."""
        self.runtime.docker.exec([*self.commandline.prefix, *argv])


def supports_strict(sub: str | None) -> bool:
    """Tells whether the compose subcommand sub can be screened with the command line untrusted.

    Parameters:
    - sub: the subcommand; None for none
    """
    return sub == "run"


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name, as the overview of docker's commands lists it.

    Parameters:
    - name: the command, as the dispatcher knows it: compose
    """
    assert name == "compose"
    return helptext.HelpTopic("dockscreen compose [OPTIONS] COMMAND",
                              "Docker Compose, with projects audited before they run")
