"""`docker compose` through dockscreen: dispatch custom subcommands, forward everything else.

We deliberately do not use argparse for the docker compose surface. Anything we
do not recognise must reach docker compose untouched, so the only thing we
parse is the position of the subcommand.
"""

import os
import sys

from dockscreen import (
    argscan,
    composeargs,
    composerun,
    config,
    flags,
    helptext,
    hostusers,
    ids,
    messages,
    policy,
    screen,
    verdict,
)
from dockscreen.commands import ALIASES, COMMANDS
from dockscreen.dockerclient import DockerNotFound
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
    """Replace this process with `docker compose argv`, keeping tty, signals and exit code."""
    binary = runtime.docker.binary
    try:
        os.execvp(binary, [binary, "compose", *argv])
    except FileNotFoundError:
        messages.fatal(messages.DOCKER_NOT_FOUND)


def main(argv=None, runtime=None):
    """runtime: the Runtime the `docker` wrapper already loaded, if it was called by that."""
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        return dispatch(argv, runtime)
    except config.ConfigError as e:
        return messages.refuse([f"config file {e}"])
    except DockerNotFound as e:
        messages.notice(e)
        return 1


def dispatch(argv, runtime=None):
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
    ids.export(runtime.env, runtime.me)

    idx = argscan.find_subcommand(argv, GLOBAL_OPTS_WITH_VALUE)
    messages.set_helpful(helpful or (idx is not None and argv[idx] == "audit"))
    target = help_request(argv, idx)
    if target is not None:
        return show_help(target, argv, idx, runtime)
    if idx is not None and argv[idx] in COMMANDS:
        return COMMANDS[argv[idx]](global_args=argv[:idx], args=argv[idx + 1:], runtime=runtime,
                                   allow_me=allow_me)

    if is_screened(argv, idx):
        if argv[idx] not in BUILD_SUBCOMMANDS:
            return composerun.run(argv, idx, runtime, allow_me=allow_me)
        if not screen.passes(argv[:idx], runtime, policy.check_build_config):
            return 1
    elif idx is not None and argv[idx] in NAMED_PROJECT_SUBCOMMANDS:
        if not name_is_free(argv[:idx], runtime):
            return 1
    elif idx is not None and argv[idx] == "exec":
        args = rewrite_exec("exec", argv[idx + 1:], runtime)
        if args is None:
            return 1
        argv = [*argv[:idx + 1], *args]

    forward(argv, runtime)


def name_is_free(global_args, runtime):
    """Whether the project's name is not that of a project made from another directory.

    Said nothing when it is. A project that cannot be inspected is left to compose to report.
    """
    if screen.names_project(global_args, runtime.env):
        return True
    try:
        config, directory = screen.inspect(global_args, runtime)
    except screen.ScreenError:
        return True
    if not config.get("name"):
        return True
    reasons = screen.name_conflicts(config["name"], directory, runtime.docker)
    return not reasons or verdict.screened(reasons)


def rewrite_exec(kind, args, runtime):
    """The arguments of `exec` (kind: "exec" or "docker exec") with --as and --as-me replaced by ids.

    None if the user they give cannot be used; that has been reported.
    """
    try:
        parsed = composeargs.parse(kind, args, runtime.me, runtime.accounts)
    except hostusers.UserError as e:
        messages.report([str(e)])
        return None
    for notice in parsed.notices:
        messages.notice(notice)
    return parsed.args


def is_screened(argv, idx):
    """Whether screening must run: SCREENED_SUBCOMMANDS (help_request has taken out help)."""
    return idx is not None and argv[idx] in SCREENED_SUBCOMMANDS


def help_request(argv, idx):
    """What help argv asks for: None for none, "" for the overview, else a command's name.

    `help`, `help COMMAND`, or --help or -h as the first argument after the command. Only a leading one
    counts: after `run SERVICE` the rest belongs to the service's command (`run app grep -h x`).
    """
    if idx is None:
        return "" if not argv or "--help" in argv or "-h" in argv else None
    if argv[idx] == "help":
        return argv[idx + 1] if idx + 1 < len(argv) else ""
    return argv[idx] if argv[idx + 1:idx + 2] in (["--help"], ["-h"]) else None


def show_help(target, argv, idx, runtime):
    """Print dockscreen's help for target, then compose's own if compose has the command too."""
    if target == "":
        helptext.show(lambda width: helptext.compose_overview(own_commands(), width))
        return forward(argv, runtime)
    if target in COMMANDS:
        helptext.show(lambda width: helptext.topic(own_commands()[ALIASES.get(target, target)], "", width))
        return 0
    if target in helptext.COMPOSE:
        helptext.show(lambda width: helptext.topic(helptext.COMPOSE[target], "Docker Compose's own", width))
    if idx is not None and argv[idx] == "help":
        argv = [*argv[:idx], target, "--help"]
    return forward(argv, runtime)


def own_commands():
    """{name: Topic} of dockscreen's own compose commands, aliases folded in."""
    return {name: helptext.command_topic(name, fn, [a for a, p in ALIASES.items() if p == name])
            for name, fn in sorted(COMMANDS.items()) if name not in ALIASES}

if __name__ == "__main__":
    sys.exit(main())
