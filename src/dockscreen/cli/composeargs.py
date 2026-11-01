"""This module provides the reading of `docker compose run` and `exec` command lines that finds the service
and the user, as userargs does for every command that runs something in a container.
"""

from collections.abc import Sequence

from dockscreen.cli import userargs
from dockscreen.host import hostusers

# Options of `docker compose run` and `exec` that take a value in the next argument.
VALUE_FLAGS = {
    "run": frozenset({
        "--cap-add", "--cap-drop", "-e", "--env", "--env-from-file", "--entrypoint", "-l", "--label",
        "--name", "-p", "--publish", "--pull", "-u", "--user", "-v", "--volume", "-w", "--workdir",
    }),
    "exec": frozenset({"-e", "--env", "--index", "-u", "--user", "-w", "--workdir"}),
}


def parse(subcommand: str, args: Sequence[str], me: tuple[int, int],
          accounts: hostusers.HostAccounts) -> userargs.Parsed:
    """Returns userargs.parse of the arguments of `run` or `exec` (subcommand)."""
    return userargs.parse(args, VALUE_FLAGS[subcommand], me, accounts)
