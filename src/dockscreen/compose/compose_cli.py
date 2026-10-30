"""`docker compose` through dockscreen: dispatch custom subcommands, forward everything else.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

from dockscreen import argscan, flags, helptext, hostusers, ids, messages, policy, verdict
from dockscreen.compose import composeargs, composerun, screen
from dockscreen.compose.commands import ALIASES, COMMANDS
from dockscreen.runtime import load_runtime

# Subcommands that create containers from the config. `alpha` is a group (older
# compose has `alpha watch`); screening it is cheap and errs on the safe side.
RUNTIME_SUBCOMMANDS = frozenset({"up", "create", "run", "watch", "scale", "alpha"})
# Subcommands that only build: they get the build-related checks, not the runtime policy.
BUILD_SUBCOMMANDS = frozenset({"build", "bake"})
SCREENED_SUBCOMMANDS = RUNTIME_SUBCOMMANDS | BUILD_SUBCOMMANDS
# Subcommands that stop, change or remove what the project's name stands for. Only the name is checked.
NAMED_PROJECT_SUBCOMMANDS = frozenset({"down", "rm", "stop", "kill", "restart", "start", "pause", "unpause"})

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


def forward(argv, runtime):
    """Replaces this process with `docker compose argv`, keeping tty, signals and exit code."""
    runtime.docker.exec(["compose", *argv])


def main(argv, runtime=None):
    """Runs `docker compose argv`, screened, and returns the exit status unless docker replaces this process.

    runtime: the Runtime the `docker` wrapper already loaded; loaded here if not given.
    Errors that stop everything (config.ConfigError, DockerNotFound) are left to docker_cli.main.
    """
    skipped, argv = flags.strip(argv, GLOBAL_OPTS_WITH_VALUE)
    if skipped:
        flags.banner()
        return forward(argv, runtime or load_runtime())  # the config file names the real docker

    allow_me, argv = flags.strip(argv, GLOBAL_OPTS_WITH_VALUE, flags.ALLOW_ME)
    helpful, argv = flags.strip_helpful(argv, GLOBAL_OPTS_WITH_VALUE)
    as_me, argv = flags.strip(argv, GLOBAL_OPTS_WITH_VALUE, flags.AS_ME)
    if as_me:
        messages.notice(flags.AS_ME_MESSAGE)
        return 2
    # a config file that cannot be trusted stops everything, before any docker runs
    runtime = runtime or load_runtime()
    # for `user: "${UID}:${GID}"` in compose files; only compose gets them, not this process
    runtime = runtime._replace(docker=runtime.docker.exporting(ids.exported(runtime.me)))
    return ComposeCommand(argv, runtime, allow_me, helpful).dispatch()


class ComposeCommand:
    """A docker compose command line, without dockscreen's own options, and what those asked for."""

    def __init__(self, argv, runtime, allow_me=False, helpful=False):
        self.argv, self.runtime, self.allow_me, self.helpful = argv, runtime, allow_me, helpful
        self.idx = argscan.find_subcommand(argv, GLOBAL_OPTS_WITH_VALUE)  # None if there is no command

    @property
    def sub(self):
        """Returns the subcommand, or None if there is none."""
        return None if self.idx is None else self.argv[self.idx]

    @property
    def global_args(self):
        """Returns the options before the subcommand, which select the project."""
        return self.argv if self.idx is None else self.argv[:self.idx]

    @property
    def args(self):
        """Returns the arguments after the subcommand."""
        return [] if self.idx is None else self.argv[self.idx + 1:]

    def dispatch(self):
        """Screens, helps with or forwards the command, and returns its exit status.

        Docker replaces this process if the command runs.
        """
        argv, sub, runtime = self.argv, self.sub, self.runtime
        messages.set_helpful(self.helpful or sub == "audit")
        target = self.help_request()
        if target is not None:
            return self.show_help(target)
        if sub in COMMANDS:
            return COMMANDS[sub](global_args=self.global_args, args=self.args, runtime=runtime,
                                 allow_me=self.allow_me)

        if self.is_screened():
            if sub not in BUILD_SUBCOMMANDS:
                return composerun.run(argv, self.idx, runtime, allow_me=self.allow_me)
            if not screen.passes(self.global_args, runtime, policy.check_build_config):
                return 1
        elif sub in NAMED_PROJECT_SUBCOMMANDS:
            if not self._name_is_free():
                return 1
        elif sub == "exec":
            args = rewrite_exec("exec", self.args, runtime)
            if args is None:
                return 1
            argv = [*argv[:self.idx + 1], *args]

        forward(argv, runtime)

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

    def is_screened(self):
        """Tells whether the subcommand is one that is screened (SCREENED_SUBCOMMANDS)."""
        return self.sub in SCREENED_SUBCOMMANDS

    def help_request(self):
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
            return forward(argv, self.runtime)
        if target in COMMANDS:
            topic = _own_commands()[ALIASES.get(target, target)]
            helptext.show(lambda width: helptext.topic(topic, "", width))
            return 0
        if target in helptext.COMPOSE:
            topic = helptext.COMPOSE[target]
            helptext.show(lambda width: helptext.topic(topic, "Docker Compose's own", width))
        if self.sub == "help":
            argv = [*self.global_args, target, "--help"]
        return forward(argv, self.runtime)


def rewrite_exec(kind, args, runtime):
    """Returns the arguments of `exec` (kind: "exec" or "docker exec") with --as and --as-me replaced by ids.

    Prints the notices of resolving names. Returns None, and reports why, if the user cannot be used.
    """
    try:
        parsed = composeargs.parse(kind, args, runtime.me, runtime.accounts)
    except hostusers.UserError as e:
        messages.report([str(e)])
        return None
    for notice in parsed.notices:
        messages.notice(notice)
    return parsed.args


def _own_commands():
    """Returns the Topics of dockscreen's own compose commands, by name, aliases folded in."""
    return {name: helptext.command_topic(name, fn, [a for a, p in ALIASES.items() if p == name])
            for name, fn in sorted(COMMANDS.items()) if name not in ALIASES}
