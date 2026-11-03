"""This module implements `docker compose` through dockscreen: the dispatch that gates or adds the subcommands
dockscreen knows and forwards everything else.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

from collections.abc import Collection, Sequence
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
from dockscreen.host import shellenv
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

# dockscreen's own subcommands, which shadow compose's of the same name; each is a callable(global_args,
# args, runtime, allow_me) that returns the exit status
COMMANDS = {"audit": compose_audit.audit, "harden": compose_harden.harden, "fix": compose_harden.harden}
ALIASES = {"fix": "harden"}  # alias -> command it stands for

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


def _passthrough(argv: Sequence[str], runtime: Runtime) -> NoReturn:
    """Replaces this process with `docker compose argv`, keeping tty, signals and exit code."""
    runtime.docker.exec(["compose", *argv])


def main(argv: Sequence[str], runtime: Runtime, given: Collection[str]) -> int:
    """Runs `docker compose argv`, screened, and returns the exit status unless docker replaces this process.

    Errors that stop everything (config.ConfigError, DockerNotFound) are left to docker_cli.main.

    Errors that stop everything (config.ConfigError, DockerNotFound) are left to docker_cli.main.

    Parameters:
    - argv: the arguments after `compose`
    - runtime: the Runtime the `docker` wrapper loaded
    - given: dockscreen's own options that the docker command line gave before `compose`
      (commandline.CommandLine.given)
    """
    command = ComposeCommand(argv, runtime, given)
    if command.skip_screening:
        commandline.banner()
        return _passthrough(command.argv, runtime)
    # for `user: "${UID}:${GID}"` in compose files; only compose gets them, not this process, and not
    # with --skip-screening, which leaves compose as it is
    command.runtime = runtime.with_docker_env(shellenv.exported(runtime.me))
    return command.dispatch()


class ComposeCommand(commandline.CommandLine):
    """Command object for one `docker compose` command line, with dockscreen's own options taken out, for
    running it through dockscreen. Its dispatch method screens, helps with or forwards the command. It holds
    the command line, as CommandLine reads it, and the runtime it runs in.

    The options before the subcommand, which select the project, are its global_args.

    Attributes:
    - runtime: the Runtime the command runs in
    """

    def __init__(self, argv: Sequence[str], runtime: Runtime, given: Collection[str] = ()) -> None:
        super().__init__(argv, GLOBAL_OPTS_WITH_VALUE, OWN_OPTIONS, given)
        self.runtime = runtime

    def dispatch(self) -> int:
        """Screens, helps with or forwards the command, and returns its exit status.

        Docker replaces this process if the command runs.
        """
        argv, sub, runtime = self.argv, self.sub, self.runtime
        messages.set_helpful(self.helpful or sub == "audit")
        if self.as_me:
            messages.notice(commandline.AS_ME_MESSAGE)
            return 2
        target = self._help_request()
        if target is not None:
            return self.show_help(target)
        if sub is None:
            return _passthrough(argv, runtime)
        if sub in COMMANDS:
            return COMMANDS[sub](global_args=self.global_args, args=self.args, runtime=runtime,
                                 allow_me=self.allow_me)

        global_args, args, allow_me = self.global_args, self.args, self.allow_me
        if self.strict and not supports_strict(sub):
            # refused, not ignored: a caller who asks for strict screening must not get the lenient kind
            return verdict.report(Report.refusal(commandline.STRICT_REFUSAL))
        if self._is_screened():
            if sub == "run":
                return compose_run.gate(global_args, args, runtime, allow_me, self.strict)
            if sub == "create":
                return compose_create.gate(global_args, args, runtime, allow_me)
            if sub in BUILD_SUBCOMMANDS:
                return compose_build.gate(global_args, sub, args, runtime)
            return compose_up.gate(global_args, sub, args, runtime, allow_me)
        if sub in NAMED_PROJECT_SUBCOMMANDS:
            return compose_lifecycle.gate(global_args, sub, args, runtime)
        if sub == "exec":
            return compose_exec.gate(global_args, args, runtime)
        _passthrough(argv, runtime)

    def _is_screened(self) -> bool:
        """Tells whether the subcommand is one that is screened (SCREENED)."""
        return self.sub in SCREENED

    def _help_request(self) -> str | None:
        """Determines what help the command line asks for: None for none, "" for the overview, else a command.

        `help`, `help COMMAND`, or --help or -h as the first argument after the command. Only a leading one
        counts: after `run SERVICE` the rest belongs to the service's command (`run app grep -h x`).
        """
        argv, idx = self.argv, self.idx
        if idx is None:
            return "" if not argv or "--help" in argv or "-h" in argv else None
        if argv[idx] == "help":
            return argv[idx + 1] if idx + 1 < len(argv) else ""
        return argv[idx] if argv[idx + 1:idx + 2] in (["--help"], ["-h"]) else None

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
        argv = self.argv
        if self.sub == "help":  # compose has no help command of its own
            argv = [*self.global_args, *([target] if target else []), "--help"]
        return _passthrough(argv, self.runtime)


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
