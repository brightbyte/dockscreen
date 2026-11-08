"""This module provides the entry point of `dockscreen` (main), a wrapper for `docker` that can also be
installed as `docker`. It reads the command line and loads the runtime, and hands both to DockerCommand.
"""

import sys
from collections.abc import Sequence

from dockscreen.commands.docker import DOCKER_OPTS_WITH_VALUE, DockerCommand
from dockscreen.host import config
from dockscreen.host.dockerclient import DockerNotFound
from dockscreen.host.runtime import load_runtime
from dockscreen.screen.report import Report
from dockscreen.util import commandline, messages


def main(argv: Sequence[str] | None = None) -> int:
    """Runs `dockscreen` with argv and returns the exit status, unless docker replaces this process.

    A config file that cannot be trusted or a missing docker is reported, with status 1.

    Parameters:
    - argv: the arguments after `dockscreen`; None for sys.argv[1:]
    """
    argv = sys.argv[1:] if argv is None else argv
    cli = commandline.main_commandline(argv, DOCKER_OPTS_WITH_VALUE, commandline.OWN_OPTIONS)
    try:
        # a config file that cannot be trusted stops everything, before any docker runs
        return DockerCommand(cli, load_runtime()).dispatch()
    except config.ConfigError as e:
        return Report.refusal(f"config file {e}").show()
    except DockerNotFound as e:
        messages.notice(e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
