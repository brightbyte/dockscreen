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
    """The `dockscreen` entry point: the exit status for argv (default sys.argv[1:]), unless docker replaces
    this process.
    """
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        return _dispatch(argv)
    except config.ConfigError as e:
        return messages.refuse([f"config file {e}"])
    except DockerNotFound as e:
        messages.notice(e)
        return 1


def _dispatch(argv):
    """The exit status for argv: dockscreen's own options taken out, then screened, helped or passed on.

    config.ConfigError and DockerNotFound are left to main.
    """
    skipped, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE)
    runtime = load_runtime()  # a config file that cannot be trusted stops everything, before any docker runs
    if skipped:
        flags.banner()
        return passthrough(argv, runtime)
    return DockerCommand.parse(argv, runtime).dispatch()


class DockerCommand:
    """A docker command line, without dockscreen's own options, and what those asked for."""

    def __init__(self, argv, runtime, allow_me=False, strict=False, helpful=False):
        self.argv, self.runtime = argv, runtime
        self.allow_me, self.strict, self.helpful = allow_me, strict, helpful
        self.idx = argscan.find_subcommand(argv, DOCKER_OPTS_WITH_VALUE)  # None if there is no command

    @classmethod
    def parse(cls, argv, runtime):
        """The command line argv, with --allow-me, --strict-screen and --helpful or --verbose taken out."""
        allow_me, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.ALLOW_ME)
        strict, argv = flags.strip(argv, DOCKER_OPTS_WITH_VALUE, flags.STRICT_SCREEN)
        helpful, argv = flags.strip_helpful(argv, DOCKER_OPTS_WITH_VALUE)
        return cls(argv, runtime, allow_me, strict, helpful)

    @property
    def sub(self):
        """The command, or None if there is none."""
        return None if self.idx is None else self.argv[self.idx]

    def dispatch(self):
        """The exit status: screened, helped or passed on; docker replaces this process if it runs."""
        argv, sub = self.argv, self.sub
        messages.set_helpful(self.helpful or sub == "audit")
        if self.strict and sub != "audit":
            # refused, not ignored: a caller who asks for strict screening must not get the lenient kind
            return messages.refuse([f"{flags.STRICT_SCREEN} is only supported for audit so far"])
        if sub is None:
            if not argv or "--help" in argv or "-h" in argv:
                helptext.show(helptext.docker_overview)
            return passthrough(argv, self.runtime)
        if sub == "help":
            return self.show_help()

        if sub == "compose":
            if self.idx != 0:
                messages.notice("docker options before `compose` are not supported")
                return 1
            lead = [*([flags.ALLOW_ME] if self.allow_me else []), *([flags.HELPFUL] if self.helpful else [])]
            return compose_cli.main([*lead, *argv[1:]], self.runtime)

        end = self.idx
        if sub == "container" and end + 1 < len(argv) and argv[end + 1] in GATED - {"audit"}:
            sub, end = argv[end + 1], end + 1
        if _wants_command_help(sub, argv[end + 1:]):
            return self._show_command_help(sub, argv)
        if (bake_args := self.bake_arguments()) is not None and bake.wants_screening(bake_args):
            return self._screened_bake(bake_args)
        if sub not in GATED:
            return passthrough(argv, self.runtime)
        return self._gated(sub, end)

    def bake_arguments(self):
        """The arguments of `buildx bake`, or None if the command is not that."""
        if self.sub != "buildx":
            return None
        rest = self.argv[self.idx + 1:]
        at = argscan.find_subcommand(rest, BUILDX_OPTS_WITH_VALUE)
        return rest[at + 1:] if at is not None and rest[at] == "bake" else None

    def _screened_bake(self, args):
        """Run `buildx bake` if the definition it would build passes the policy for builds."""
        reasons, failed = bake.screen(self.runtime.docker, args)
        if not verdict.screened(reasons, failed):
            return 1
        return passthrough(self.argv, self.runtime)

    def _gated(self, sub, end):
        """Run the GATED command sub (argv[end]) through the gate; if it passes, docker replaces us."""
        argv, runtime = self.argv, self.runtime
        lead, args = argv[:end + 1], argv[end + 1:]
        if sub == "audit" and not args:
            messages.notice(gate.AUDIT_USAGE)
            messages.notice("Run 'dockscreen audit --help' for more.")
            return 2
        if sub in ("run", "create") and not args:
            return passthrough(argv, runtime)  # docker says what is missing
        if sub == "create":
            try:
                resolved = gate.create_args(args, runtime)
            except hostusers.UserError as e:
                return messages.refuse([str(e)])
            messages.notice(gate.defaults_notice())
            return passthrough([*lead, *gate.DEFAULTS, *resolved], runtime)
        if sub == "exec":
            resolved = compose_cli.rewrite_exec("docker exec", args, runtime)
            return 1 if resolved is None else passthrough([*lead, *resolved], runtime)

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
        return passthrough(argv, runtime)

    def show_help(self):
        """`help` and `help COMMAND`: dockscreen's help, then docker's own."""
        rest = self.argv[self.idx + 1:]
        if not rest:
            helptext.show(helptext.docker_overview)
            return passthrough(self.argv, self.runtime)
        if rest[0] == "compose":
            return compose_cli.main(["help", *rest[1:]], self.runtime)
        return self._show_command_help(rest[0], [rest[0], "--help"])

    def _show_command_help(self, name, argv):
        """dockscreen's help for command name, if it has one, then docker's own (argv asks for it)."""
        topic = helptext.DOCKER.get(name)
        if topic is not None:
            helptext.show(lambda width: helptext.topic(topic, "Docker's own", width))
            if not topic.docker_help:
                return 0
        return passthrough(argv, self.runtime)


def _wants_command_help(sub, args):
    """--help, or -h, as the first argument after the command. For run and create, -h is --hostname."""
    return args[:1] == ["--help"] or (args[:1] == ["-h"] and sub not in ("run", "create"))


def passthrough(argv, runtime):
    """Replace this process with the real docker."""
    runtime.docker.exec(argv)


if __name__ == "__main__":
    sys.exit(main())
