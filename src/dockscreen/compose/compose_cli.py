"""`docker compose` through dockscreen: dispatch custom subcommands, forward everything else.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

from dockscreen import commandline, helptext, ids, messages, policy, userargs, verdict
from dockscreen.compose import audit, composeargs, gate, screen

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
COMMANDS = {"audit": audit.audit, "harden": audit.harden, "fix": audit.harden}
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


def _passthrough(argv, runtime):
    """Replaces this process with `docker compose argv`, keeping tty, signals and exit code."""
    runtime.docker.exec(["compose", *argv])


def main(argv, runtime, given):
    """Runs `docker compose argv`, screened, and returns the exit status unless docker replaces this process.

    runtime: the Runtime the `docker` wrapper loaded. given: dockscreen's own options that the docker
    command line gave before `compose` (commandline.CommandLine.given).
    Errors that stop everything (config.ConfigError, DockerNotFound) are left to docker_cli.main.
    """
    command = ComposeCommand(argv, runtime, given)
    if command.skip_screening:
        commandline.banner()
        return _passthrough(command.argv, runtime)
    # for `user: "${UID}:${GID}"` in compose files; only compose gets them, not this process, and not
    # with --skip-screening, which leaves compose as it is
    command.runtime = runtime._replace(docker=runtime.docker.with_env(ids.exported(runtime.me)))
    return command.dispatch()


class ComposeCommand(commandline.CommandLine):
    """A docker compose command line, without dockscreen's own options, and what those asked for.

    global_args are the options before the subcommand, which select the project.
    """

    def __init__(self, argv, runtime, given=()):
        super().__init__(argv, GLOBAL_OPTS_WITH_VALUE, OWN_OPTIONS, given)
        self.runtime = runtime

    def dispatch(self):
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
        if sub in COMMANDS:
            return COMMANDS[sub](global_args=self.global_args, args=self.args, runtime=runtime,
                                 allow_me=self.allow_me)

        if self._is_screened():
            if sub not in BUILD_SUBCOMMANDS:
                return gate.run(self.global_args, sub, self.args, runtime, allow_me=self.allow_me)
            if not screen.passes(self.global_args, runtime, policy.check_build_config):
                return 1
        elif sub in NAMED_PROJECT_SUBCOMMANDS:
            if not self._name_is_free():
                return 1
        elif sub == "exec":
            args = userargs.resolved(self.args, composeargs.VALUE_FLAGS["exec"], runtime)
            if args is None:
                return 1
            argv = [*argv[:self.idx + 1], *args]

        _passthrough(argv, runtime)

    def _name_is_free(self):
        """Tells whether the project's name is free: chosen on the command line, or not used by containers
        made from another directory.

        Reports the conflict if it is not. A project that cannot be inspected is left to compose to report.
        """
        runtime = self.runtime
        if screen.names_project(self.global_args, runtime.env):
            return True
        try:
            config, directory = screen.inspect(self.global_args, runtime)
        except screen.ScreenError:
            return True
        if not config.get("name"):
            return True
        reasons = screen.name_conflicts(config["name"], directory, runtime.docker)
        return not reasons or verdict.screened(reasons)

    def _is_screened(self):
        """Tells whether the subcommand is one that is screened (SCREENED)."""
        return self.sub in SCREENED

    def _help_request(self):
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

    def show_help(self, target):
        """Prints dockscreen's help for target, then forwards to compose's own help if it has one."""
        argv = self.argv
        if target == "":
            helptext.show(lambda width: helptext.compose_overview(_own_commands(), width))
            return _passthrough(argv, self.runtime)
        if target in COMMANDS:
            topic = _own_commands()[ALIASES.get(target, target)]
            helptext.show(lambda width: helptext.topic(topic, "", width))
            return 0
        if target in helptext.COMPOSE:
            topic = helptext.COMPOSE[target]
            helptext.show(lambda width: helptext.topic(topic, "Docker Compose's own", width))
        if self.sub == "help":
            argv = [*self.global_args, target, "--help"]
        return _passthrough(argv, self.runtime)


def _own_commands():
    """Returns the Topics of dockscreen's own compose commands, by name, aliases folded in."""
    return {name: helptext.command_topic(name, fn, [a for a, p in ALIASES.items() if p == name])
            for name, fn in sorted(COMMANDS.items()) if name not in ALIASES}
