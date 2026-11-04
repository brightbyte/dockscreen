"""This module implements `docker compose` through dockscreen: it reads compose's part of the command line
and hands it to ComposeCommand, which dispatches to the compose commands.
"""

from dockscreen.compose.command import ComposeCommand
from dockscreen.host import shellenv
from dockscreen.host.runtime import Runtime
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
