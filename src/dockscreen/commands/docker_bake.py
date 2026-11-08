"""This module implements `docker buildx bake`, checking what the project's bake files let the builds reach
on this host.

Bake reads files the project controls (docker-bake.hcl, compose files with `x-bake`), as `compose build`
does, so the same things are refused: build sources outside the project, host networking, the SSH
agent. Bake adds ways to write to the host (`output`, `cache-to`) and to read files and variables
(`secret`).

`docker buildx bake --print` gives the definition that would be built, with the command line applied
(`--set`, `--push`, targets), and builds nothing. The policy judges it as such (Policy.check_bake): a key
that is not known is refused, because a new one may be a new way out.
"""
import json
from collections.abc import Collection
from typing import Any

from dockscreen.host.dockerclient import Docker, DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.model.build import BakeDefinition
from dockscreen.screen import findings, policy
from dockscreen.screen.findings import Finding
from dockscreen.screen.report import Report
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline

NOT_SCREENED = {"--print", "--help", "-h"}  # builds nothing


def _wants_screening(args: Collection[str]) -> bool:
    """Tells whether `bake` with these arguments builds, and so needs screening."""
    return not NOT_SCREENED & set(args)


def _definition(docker: Docker, bake: commandline.CommandLine) -> dict[str, Any]:
    """Returns the bake definition for the command line, as `--print` gives it, without building anything.

    It is asked for with the options before `buildx` and `bake`, which choose the daemon and the builder.

    Raises DockerError, saying why, if docker cannot give one or it is not a JSON object.
    """
    result = docker.capture([docker.binary, *bake.global_args, "bake", "--print", *bake.args])
    if result.returncode != 0:
        raise DockerError("docker buildx bake --print failed", result.stderr.strip())
    try:
        found = json.loads(result.stdout)
    except ValueError as e:
        raise DockerError(f"cannot read the bake definition: {e}") from e
    if not isinstance(found, dict):
        raise DockerError("cannot read the bake definition: not an object")
    return found


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker buildx bake` if the definition it would build passes the policy for builds; returns 1 if
    it does not, otherwise docker replaces this process. With --print or --help it builds nothing, and runs
    unchecked.

    Parameters:
    - parent_cli: buildx's part of the command line, with `bake` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "bake"
    if _wants_screening(parent_cli.args):
        bake_policy = Screener(runtime).policy(runtime.cwd)
        if not Report.of(check(runtime.docker, parent_cli, bake_policy, runtime.cwd)).show_screening():
            return 1
    runtime.docker.exec(parent_cli.full_argv)


def check(docker: Docker, bake: commandline.CommandLine, bake_policy: policy.Policy, directory: str
          ) -> list[Finding]:
    """Checks the `bake` command line, run in directory, by bake_policy.

    Returns why it may not run: refusals, or the failure to get the definition.

    Parameters:
    - docker: the docker to run bake with
    - bake: buildx's part of the command line, with `bake` as its command
    - bake_policy: the policy for builds
    - directory: the directory bake runs in, which its relative paths are relative to
    """
    try:
        found = _definition(docker, bake)
    except DockerError as e:
        hint = "fix the bake files, or use --print to see what docker makes of them"
        return [findings.failure_of(e, help=hint)]
    return bake_policy.check_bake(BakeDefinition(found, directory))
