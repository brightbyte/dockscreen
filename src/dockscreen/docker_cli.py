"""Entry point: `dockscreen`, a wrapper for `docker`, which can also be installed as `docker`.

`compose` goes to compose_cli, commands that start containers from images
go through the gate, everything else is exec'd to the real docker unchanged.
"""

import sys

from dockscreen import argscan, bake, config, flags, helptext, hostusers, imagedecision, messages, verdict
from dockscreen.compose import compose_cli, screen
from dockscreen.dockerclient import DockerNotFound
from dockscreen.run import gate
from dockscreen.runtime import load_runtime
from dockscreen.verdict import Verdict

# Global `docker` options that consume the following token as their value.
DOCKER_OPTS_WITH_VALUE = frozenset({
    "--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
    "--tlscacert", "--tlscert", "--tlskey",
})
GATED = frozenset({"run", "create", "start", "restart", "exec", "audit"})
BUILDX_OPTS_WITH_VALUE = frozenset({"--builder"})


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
    skipped, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE)
    if skipped:
        flags.banner()
        return _passthrough(argv, runtime)
    return DockerCommand.parse(argv, runtime).dispatch()


class DockerCommand:
    """A docker command line, without dockscreen's own options, and what those asked for."""

    def __init__(self, argv, runtime, allow_me=False, strict=False, helpful=False):
        self.argv, self.runtime = argv, runtime
        self.allow_me, self.strict, self.helpful = allow_me, strict, helpful
        self.idx = argscan.find_subcommand(argv, DOCKER_OPTS_WITH_VALUE)  # None if there is no command

    @classmethod
    def parse(cls, argv, runtime):
        """Builds the command for argv, taking out --allow-me, --strict-screen and --helpful or --verbose."""
        allow_me, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.ALLOW_ME)
        strict, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.STRICT_SCREEN)
        helpful, argv = flags.strip_helpful(argv, DOCKER_OPTS_WITH_VALUE)
        return cls(argv, runtime, allow_me, strict, helpful)

    @property
    def sub(self):
        """Returns the docker command (the first argument that is not a global option), or None."""
        return None if self.idx is None else self.argv[self.idx]

    def dispatch(self):
        """Runs the command, screened, helped or passed on, and returns the exit status, unless docker
        replaces this process.
        """
        argv, sub = self.argv, self.sub
        messages.set_helpful(self.helpful or sub == "audit")
        if self.strict and sub != "audit":
            # refused, not ignored: a caller who asks for strict screening must not get the lenient kind
            return messages.refuse([f"{flags.STRICT_SCREEN} is only supported for audit so far"])
        if sub is None:
            if not argv or "--help" in argv or "-h" in argv:
                helptext.show(helptext.docker_overview)
            return _passthrough(argv, self.runtime)
        if sub == "help":
            return self.show_help()

        if sub == "compose":
            if self.idx != 0:  # compose_cli gets what follows `compose`: these would not reach it
                messages.notice("docker options before `compose` are not supported")
                return 1
            lead = [*([flags.ALLOW_ME] if self.allow_me else []), *([flags.HELPFUL] if self.helpful else [])]
            return compose_cli.main([*lead, *argv[1:]], self.runtime)

        end = self.idx
        # `docker container run` is `docker run`; audit is ours and has no such form
        if sub == "container" and end + 1 < len(argv) and argv[end + 1] in GATED - {"audit"}:
            sub, end = argv[end + 1], end + 1
        if _wants_command_help(sub, argv[end + 1:]):
            return self._show_command_help(sub, argv)
        if (bake_args := self._bake_arguments()) is not None and bake.wants_screening(bake_args):
            return self._screened_bake(bake_args)
        if sub not in GATED:
            return _passthrough(argv, self.runtime)
        return self._gated(sub, end)

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
        """Runs the GATED command sub (argv[end]) through the gate and returns the exit status, unless it
        passes and docker replaces this process.
        """
        argv, runtime = self.argv, self.runtime
        lead, args = argv[:end + 1], argv[end + 1:]
        if sub == "audit" and not args:
            messages.notice(gate.AUDIT_USAGE)
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
            resolved = compose_cli.rewrite_exec("docker exec", args, runtime)
            return 1 if resolved is None else _passthrough([*lead, *resolved], runtime)

        docker = runtime.docker
        if screen.is_remote(argv[:self.idx], runtime.env, docker):
            return verdict.report(Verdict.REFUSED, [screen.REMOTE_MESSAGE])

        ctx = imagedecision.Context(docker, runtime.rules(self.allow_me), runtime)
        if sub == "run":
            return gate.run(ctx, args)
        if sub == "audit":
            return gate.audit(ctx, args, self.strict)
        if not verdict.screened(gate.check_existing(ctx, args)):
            return 1
        return _passthrough(argv, runtime)

    def show_help(self):
        """Prints dockscreen's help for `help` or `help COMMAND`, then passes on to docker for its own."""
        rest = self.argv[self.idx + 1:]
        if not rest:
            helptext.show(helptext.docker_overview)
            return _passthrough(self.argv, self.runtime)
        if rest[0] == "compose":
            return compose_cli.main(["help", *rest[1:]], self.runtime)
        return self._show_command_help(rest[0], [rest[0], "--help"])

    def _show_command_help(self, name, argv):
        """Prints dockscreen's help for command name, if it has one, then runs argv for docker's own.

        Returns 0 if docker has no help to add.
        """
        topic = helptext.DOCKER.get(name)
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
