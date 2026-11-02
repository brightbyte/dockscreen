"""This module is the docker that dockscreen runs in the end-to-end tests: it hands every call to the real
docker, except the ones that would start, stop or change containers or write a build's output.

Those are where dockscreen hands over once its checks have passed (the hand-off). They are recorded and
answered with success, so that a test can see exactly what dockscreen would have run, and nothing starts.
Every call is recorded, as one JSON object per line in the file DOCKSCREEN_E2E_CALLS names:

- argv: the arguments, without the binary;
- held: whether it was a hand-off, which did not reach docker;
- files: for a hand-off, the content of each file given with -f or --file, which dockscreen removes once
  compose returns;
- env: for a hand-off, the variables dockscreen sets for compose;
- created: for `create`, the id of the container docker made, so that the test can look at it and remove it.

It runs as a script, with only the standard library, and DOCKSCREEN_E2E_REAL_DOCKER names the real docker.
"""

import json
import os
import subprocess
import sys

# Global options of docker, and of docker compose, that take the next argument as their value.
DOCKER_VALUE_OPTIONS = frozenset({
    "--config", "-c", "--context", "-H", "--host", "-l", "--log-level",
    "--tlscacert", "--tlscert", "--tlskey",
})
COMPOSE_VALUE_OPTIONS = frozenset({
    "--ansi", "--env-file", "-f", "--file", "--parallel", "--profile", "--progress", "--project-directory",
    "-p", "--project-name",
})
# What starts, stops or changes containers. `rm` and `create` are not here: dockscreen removes and creates
# the containers it looks at itself, and a created container never starts.
HELD_DOCKER = frozenset({"run", "start", "restart", "exec", "attach", "stop", "kill", "pause", "unpause"})
HELD_COMPOSE = frozenset({
    "up", "create", "run", "scale", "watch", "alpha", "start", "restart", "stop", "kill", "down", "rm",
    "pause", "unpause", "exec", "attach", "bake",
})
# What dockscreen passes to compose, and the variables that decide which daemon and project it uses.
RECORDED_ENV = ("UID", "GID", "COMPOSE_PROJECT_NAME", "DOCKER_HOST", "DOCKER_CONTEXT", "HOME")


def subcommand(argv: list[str], value_options: frozenset[str]) -> int | None:
    """Returns the index of the first argument that is not an option or an option's value, or None."""
    i = 0
    while i < len(argv):
        if argv[i] in value_options:
            i += 2
        elif argv[i].startswith("-"):
            i += 1
        else:
            return i
    return None


def command(argv: list[str]) -> tuple[str, ...]:
    """Returns the command argv runs: ("run",), ("compose", "up"), ("buildx", "bake") and so on."""
    at = subcommand(argv, DOCKER_VALUE_OPTIONS)
    if at is None:
        return ()
    name, rest = argv[at], argv[at + 1:]
    if name in ("container", "compose", "buildx"):
        inner = subcommand(rest, COMPOSE_VALUE_OPTIONS if name == "compose" else frozenset({"--builder"}))
        if inner is not None:
            return (name, rest[inner]) if name != "container" else (rest[inner],)
    return (name,)


def is_handoff(argv: list[str]) -> bool:
    """Tells whether argv would start, stop or change containers, or write a build's output."""
    found = command(argv)
    if found[:1] == ("compose",):
        return len(found) > 1 and found[1] in HELD_COMPOSE
    if found == ("buildx", "bake"):
        return "--print" not in argv
    return found[:1] != () and found[0] in HELD_DOCKER


def named_files(argv: list[str]) -> dict[str, str]:
    """Returns {path: content} of the files argv gives with -f or --file; "" for one that cannot be read."""
    paths = [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg in ("-f", "--file")]
    paths += [arg.partition("=")[2] for arg in argv if arg.startswith("--file=")]
    files = {}
    for path in paths:
        try:
            with open(path) as f:
                files[path] = f.read()
        except OSError:
            files[path] = ""
    return files


def record(entry: dict) -> None:
    """Appends entry to the call log."""
    with open(os.environ["DOCKSCREEN_E2E_CALLS"], "a") as f:
        f.write(json.dumps(entry) + "\n")


def main(argv: list[str]) -> int:
    real = os.environ["DOCKSCREEN_E2E_REAL_DOCKER"]
    if is_handoff(argv):
        record({"argv": argv, "held": True, "files": named_files(argv),
                "env": {name: os.environ.get(name) for name in RECORDED_ENV}})
        return 0
    if command(argv) == ("create",):
        # stderr stays where it is: pull progress and docker's errors show as they would
        done = subprocess.run([real, *argv], stdout=subprocess.PIPE, text=True, check=False)
        created = done.stdout.strip() if done.returncode == 0 else None
        record({"argv": argv, "held": False, "created": created})
        sys.stdout.write(done.stdout)
        return done.returncode
    record({"argv": argv, "held": False})
    os.execv(real, [real, *argv])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
