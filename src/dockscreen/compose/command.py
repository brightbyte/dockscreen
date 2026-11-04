"""This module implements `docker compose` through dockscreen: the dispatch that gates or adds the subcommands
dockscreen knows and forwards everything else.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import NoReturn

from dockscreen import helptext
from dockscreen.commands import (
    compose_audit,
    compose_build,
    compose_create,
    compose_exec,
    compose_harden,
    compose_lifecycle,
    compose_run,
    compose_up,
)
from dockscreen.host.runtime import Runtime
from dockscreen.screen import verdict
from dockscreen.screen.findings import Report
from dockscreen.util import commandline, messages

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
            return verdict.report(Report.refusal(commandline.STRICT_REFUSAL))
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
            helptext.show(lambda width: helptext.compose_overview(_own_commands(), width))
        elif target in COMMANDS:
            topic = _own_commands()[ALIASES.get(target, target)]
            helptext.show(lambda width: helptext.topic(topic, "", width))
            return 0
        elif target in helptext.COMPOSE:
            topic = helptext.COMPOSE[target]
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


def _own_commands() -> dict[str, helptext.Topic]:
    """Returns the Topics of dockscreen's own compose commands, by name, aliases folded in."""
    return {name: helptext.command_topic(name, fn, [a for a, p in ALIASES.items() if p == name])
            for name, fn in sorted(COMMANDS.items()) if name not in ALIASES}
