"""Entry point: `dockscreen`, a wrapper for `docker`, which can also be installed as `docker`.

`compose` goes to compose_cli, commands that start containers from images
go through the gate, everything else is exec'd to the real docker unchanged.
"""

import sys

from dockscreen import argscan, bake, config, flags, helptext, hostusers, messages, userargs, verdict
from dockscreen.compose import compose_cli
from dockscreen.dockerclient import DockerNotFound
from dockscreen.run import audit, gate, runargs
from dockscreen.runtime import load_runtime

# Global `docker` options that consume the following token as their value.
DOCKER_OPTS_WITH_VALUE = frozenset({
    "--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
    "--tlscacert", "--tlscert", "--tlskey",
})
# Commands that start a container or run in one, and our audit: they go through the gate.
SCREENED = frozenset({"run", "create", "start", "restart", "exec", "audit"})
BUILDX_OPTS_WITH_VALUE = frozenset({"--builder"})
# dockscreen's own options before the docker command
OWN_OPTIONS = frozenset({
    flags.SKIP_SCREENING, flags.ALLOW_ME, flags.STRICT_SCREEN, flags.HELPFUL, flags.VERBOSE,
})


def main(argv=None):
    """Runs `dockscreen` with argv (default sys.argv[1:]) and returns the exit status, unless docker
    replaces this process.

    A config file that cannot be trusted or a missing docker is reported, with status 1.
    """
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        # a config file that cannot be trusted stops everything, before any docker runs
        return _dispatch(argv, load_runtime())
    except config.ConfigError as e:
        return messages.refuse([f"config file {e}"])
    except DockerNotFound as e:
        messages.notice(e)
        return 1


def _dispatch(argv, runtime):
    """Runs the docker command line argv as dockscreen and returns the exit status, unless docker replaces
    this process. --skip-screening passes argv on unchecked.

    Raises DockerNotFound for main to report.
    """
    command = DockerCommand(argv, runtime)
    if command.skip_screening:
        flags.banner()
        return _passthrough(command.argv, runtime)
    return command.dispatch()


class DockerCommand(flags.CommandLine):
    """A docker command line, without dockscreen's own options, and what those asked for."""

    def __init__(self, argv, runtime):
        super().__init__(argv, DOCKER_OPTS_WITH_VALUE, OWN_OPTIONS)
        self.runtime = runtime

    def dispatch(self):
        """Runs the command, screened, helped or passed on, and returns the exit status, unless docker
        replaces this process.
        """
        argv, sub = self.argv, self.sub
        messages.set_helpful(self.helpful or sub == "audit")
        if self.strict and sub != "audit":
            # refused, not ignored: a caller who asks for strict screening must not get the lenient kind
            return messages.refuse([f"{flags.STRICT_SCREEN} is only supported for audit so far"])
        target = self._help_request()
        if target is not None:
            return self.show_help(target)
        if sub is None:
            return _passthrough(argv, self.runtime)

        if sub == "compose":
            if self.idx != 0:  # compose_cli gets what follows `compose`: these would not reach it
                messages.notice("docker options before `compose` are not supported")
                return 1
            return compose_cli.main(argv[1:], self.runtime, self.given)

        if (bake_args := self._bake_arguments()) is not None and bake.wants_screening(bake_args):
            return self._screened_bake(bake_args)
        sub, end = self._command()
        if sub not in SCREENED:
            return _passthrough(argv, self.runtime)
        return self._gated(sub, end)

    def _command(self):
        """Returns (name, index) of the command: `docker container run` is `run`, at the index of `run`."""
        argv, end = self.argv, self.idx
        # audit is ours and has no such form
        if argv[end] == "container" and end + 1 < len(argv) and argv[end + 1] in SCREENED - {"audit"}:
            end += 1
        return argv[end], end

    def _bake_arguments(self):
        """Returns the arguments of `buildx bake`, or None if the command is not that."""
        if self.sub != "buildx":
            return None
        rest = self.argv[self.idx + 1:]
        at = argscan.find_subcommand(rest, BUILDX_OPTS_WITH_VALUE)
        return rest[at + 1:] if at is not None and rest[at] == "bake" else None

    def _screened_bake(self, args):
        """Runs `buildx bake` with args if the definition it would build passes the policy for builds.

        Returns 1 if it does not; otherwise docker replaces this process.
        """
        reasons, failed = bake.screen(self.runtime.docker, args)
        if not verdict.screened(reasons, failed):
            return 1
        return _passthrough(self.argv, self.runtime)

    def _gated(self, sub, end):
        """Runs the SCREENED command sub (argv[end]) through the gate and returns the exit status, unless it
        passes and docker replaces this process.
        """
        argv, runtime = self.argv, self.runtime
        global_args, lead, args = argv[:self.idx], argv[:end + 1], argv[end + 1:]
        if sub == "audit" and not args:
            messages.notice(audit.AUDIT_USAGE)
            messages.notice("Run 'dockscreen audit --help' for more.")
            return 2
        if sub in ("run", "create") and not args:
            return _passthrough(argv, runtime)  # docker says what is missing
        if sub == "create":
            try:
                resolved = gate.create_args(args, runtime)
            except hostusers.UserError as e:
                return messages.refuse([str(e)])
            messages.notice(gate.defaults_notice())
            return _passthrough([*lead, *gate.DEFAULTS, *resolved], runtime)
        if sub == "exec":
            resolved = userargs.resolved(args, runargs.EXEC_VALUE_FLAGS, runtime)
            return 1 if resolved is None else _passthrough([*lead, *resolved], runtime)
        if sub == "run":
            return gate.run(global_args, args, runtime, self.allow_me)
        if sub == "audit":
            return audit.audit(global_args, args, runtime, self.allow_me, self.strict)
        if not verdict.screened(gate.check_existing(global_args, args, runtime, self.allow_me)):
            return 1
        return _passthrough(argv, runtime)

    def _help_request(self):
        """Determines what help the command line asks for: None for none, "" for the overview, else a command.

        `help`, `help COMMAND`, or --help or -h as the first argument after the command; for run and create,
        -h is --hostname. `compose` gives its own help (compose_cli), except for `help compose`.
        """
        argv, idx = self.argv, self.idx
        if idx is None:
            return "" if not argv or "--help" in argv or "-h" in argv else None
        if argv[idx] == "help":
            return argv[idx + 1] if idx + 1 < len(argv) else ""
        if argv[idx] == "compose":
            return None
        sub, end = self._command()
        return sub if _wants_command_help(sub, argv[end + 1:]) else None

    def show_help(self, target):
        """Prints dockscreen's help for target, then passes on to docker for its own if it has one."""
        if target == "":
            helptext.show(helptext.docker_overview)
            return _passthrough(self.argv, self.runtime)
        if target == "compose":
            return compose_cli.main(["help", *self.argv[self.idx + 2:]], self.runtime, self.given)
        argv = self.argv
        if self.sub == "help":
            argv = [*argv[:self.idx], target, "--help"]
        topic = helptext.DOCKER.get(target)
        if topic is not None:
            helptext.show(lambda width: helptext.topic(topic, "Docker's own", width))
            if not topic.docker_help:
                return 0
        return _passthrough(argv, self.runtime)


def _wants_command_help(sub, args):
    """Tells whether args ask for help: --help, or -h, first. For run and create, -h is --hostname."""
    return args[:1] == ["--help"] or (args[:1] == ["-h"] and sub not in ("run", "create"))


def _passthrough(argv, runtime):
    """Replaces this process with the real docker, run with argv."""
    runtime.docker.exec(argv)


if __name__ == "__main__":
    sys.exit(main())
