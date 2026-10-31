"""The options of `docker compose run` and `exec`, as userargs reads them."""

from dockscreen import userargs

# Options of `docker compose run` and `exec` that take a value in the next argument.
VALUE_FLAGS = {
    "run": frozenset({
        "--cap-add", "--cap-drop", "-e", "--env", "--env-from-file", "--entrypoint", "-l", "--label",
        "--name", "-p", "--publish", "--pull", "-u", "--user", "-v", "--volume", "-w", "--workdir",
    }),
    "exec": frozenset({"-e", "--env", "--index", "-u", "--user", "-w", "--workdir"}),
}


def parse(subcommand, args, me, accounts):
    """Returns userargs.parse of the arguments of `run` or `exec` (subcommand)."""
    return userargs.parse(args, VALUE_FLAGS[subcommand], me, accounts)
