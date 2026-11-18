"""This module implements `docker` through dockscreen. Its dispatch gates or adds the commands that dockscreen
knows, and hands everything else to the real docker.

`compose` goes to docker_compose, and commands that start containers from images go through the gate (GATES).
dockscreen execs everything else to the real docker unchanged.
"""

from collections.abc import Callable, Mapping, Sequence
from types import MappingProxyType
from typing import NoReturn

from dockscreen.commands import (
    docker_bake,
    docker_compose,
    docker_create,
    docker_exec,
    docker_run,
    docker_start,
    helptext,
)
from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.util import commandline, messages

# Global `docker` options that consume the following token as their value.
DOCKER_OPTS_WITH_VALUE = frozenset({
    "--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
    "--tlscacert", "--tlscert", "--tlskey",
})
# Commands that start a container or run in one: they go through the gate.
GATES = MappingProxyType({
    "run": docker_run.gate,
    "create": docker_create.gate,
    "start": docker_start.gate,
    "restart": docker_start.gate,
    "exec": docker_exec.gate,
})

BUILDX_OPTS_WITH_VALUE = frozenset({"--builder"})
# dockscreen's own help, for each command that has one
HELP: Mapping[str, Callable[[str], helptext.HelpTopic]] = MappingProxyType({
    "run": docker_run.help,
    "create": docker_create.help,
    "start": docker_start.help,
    "restart": docker_start.help,
    "exec": docker_exec.help,
    "audit": docker_run.help,
    "compose": docker_compose.help,
})


class DockerCommand:
    """Command object for one `docker` command line, with dockscreen's own options taken out, for running it
    through dockscreen. Its dispatch method screens, helps with or hands on the command. It holds the command
    line, as main_commandline reads it, and the runtime it runs in.

    Attributes:
    - commandline: the command line
    - runtime: the Runtime the command runs in
    """

    def __init__(self, cli: commandline.CommandLine, runtime: Runtime) -> None:
        self.commandline = cli
        self.runtime = runtime

    def dispatch(self) -> int:
        """Runs the command, which it screens, helps with or passes on. Returns the exit status, unless docker
        replaces this process.
        """
        cli = _short_form(self.commandline)
        argv, cmd = cli.argv, cli.cmd
        messages.set_helpful(cli.is_helpful or cmd == "audit")
        if cli.is_screening_skipped:
            for warning in commandline.SKIP_SCREENING_WARNINGS:
                messages.print_warning(warning)
            return _passthrough(argv, self.runtime)
        target = _help_request(cli)
        if target is not None:
            return self.show_help(cli, target)
        if cli.is_me_allowed and cmd != "compose":
            return Report.refusal(commandline.ALLOW_ME_REFUSAL).show()
        if cmd == "audit":
            return docker_run.audit(cli, self.runtime)
        if cmd == "compose":
            return docker_compose.gate(cli, self.runtime)
        if cmd == "buildx":
            buildx_cli = cli.subcommand(BUILDX_OPTS_WITH_VALUE)
            if buildx_cli.cmd == "bake":
                return docker_bake.gate(buildx_cli, self.runtime)
        if cmd in ("run", "create") and not cli.args:
            return _passthrough(argv, self.runtime)  # docker says what is missing
        if cmd is not None and cmd in GATES:
            return GATES[cmd](cli, self.runtime)
        if cli.is_strict:
            # refused, not ignored: a user who asks for strict screening must not get the lenient kind.
            # Every command above that does not support --strict-screen refuses it itself.
            return Report.refusal(commandline.STRICT_REFUSAL).show()
        return _passthrough(argv, self.runtime)

    def show_help(self, cli: commandline.CommandLine, target: str) -> int:
        """Prints dockscreen's help for target, then passes on to docker for docker's own help, if docker has
        one.

        Parameters:
        - cli: the command line that asks for help
        - target: the command to give the help of; "" for dockscreen itself
        """
        if target == "":
            topics = helptext.topics(HELP)
            helptext.show(lambda width: helptext.docker_overview(topics, width))
            return _passthrough(cli.argv, self.runtime)
        if target == "compose":  # after help compose
            compose_cli = commandline.CommandLine("help", cli.args[1:], own_args=cli.own_args,
                                                  prefix=[*cli.lead_args, "compose"])
            return docker_compose.ComposeCommand(compose_cli, self.runtime).dispatch()
        argv = cli.argv
        if cli.cmd == "help":
            argv = [*cli.lead_args, target, "--help"]
        if target in HELP:
            topic = HELP[target](target)
            helptext.show(lambda width: helptext.topic_lines(topic, "Docker's own", width))
            if not topic.has_docker_help:
                return 0
        return _passthrough(argv, self.runtime)


def _short_form(cli: commandline.CommandLine) -> commandline.CommandLine:
    """Returns cli, with `docker container run` and the other gated commands read in their short form, such as
    `docker run`: they are the same commands. `container audit` is not ours, so it stays as it is, and so does
    anything else after `container`.
    """
    if cli.cmd != "container" or not cli.args or cli.args[0] not in GATES:
        return cli
    return cli.subcommand(should_inherit_lead=True)


def _help_request(cli: commandline.CommandLine) -> str | None:
    """Determines the help that the command line asks for: None for none, "" for the overview, else a command.

    The command line asks for help with `help`, with `help COMMAND`, or with --help or -h as the first
    argument after the command. For run and create, -h means --hostname. `compose` gives its own help
    (ComposeCommand), except for `help compose`.
    """
    if cli.cmd is None:
        lead_args = cli.lead_args
        return "" if not lead_args or "--help" in lead_args or "-h" in lead_args else None
    if cli.cmd == "help":
        return cli.args[0] if cli.args else ""
    if cli.cmd == "compose":
        return None
    return cli.cmd if _wants_command_help(cli.cmd, cli.args) else None


def _wants_command_help(sub: str, args: Sequence[str]) -> bool:
    """Tells whether args ask for help, with --help or -h as the first argument. For run and create, -h is
    --hostname.
    """
    first_arg = tuple(args[:1])
    return first_arg == ("--help",) or (first_arg == ("-h",) and sub not in ("run", "create"))


def _passthrough(argv: Sequence[str], runtime: Runtime) -> NoReturn:
    """Replaces this process with the real docker, run with argv."""
    runtime.docker.exec(argv)
