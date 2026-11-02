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
from collections.abc import Collection, Sequence
from typing import Any

from dockscreen.host.dockerclient import Docker, DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.model.build import BakeDefinition
from dockscreen.screen import findings, policy, verdict
from dockscreen.screen.findings import Finding, Report
from dockscreen.screen.scope import Scope

NOT_SCREENED = {"--print", "--help", "-h"}  # builds nothing


def wants_screening(args: Collection[str]) -> bool:
    """Tells whether `bake` with these arguments builds, and so needs screening."""
    return not NOT_SCREENED & set(args)


def _definition(docker: Docker, args: Sequence[str]) -> dict[str, Any]:
    """Returns the bake definition for the arguments, as `--print` gives it, without building anything.

    Raises DockerError, saying why, if docker cannot give one or it is not a JSON object.
    """
    result = docker.capture([docker.binary, "buildx", "bake", "--print", *args])
    if result.returncode != 0:
        raise DockerError("docker buildx bake --print failed", result.stderr.strip())
    try:
        found = json.loads(result.stdout)
    except ValueError as e:
        raise DockerError(f"cannot read the bake definition: {e}") from e
    if not isinstance(found, dict):
        raise DockerError("cannot read the bake definition: not an object")
    return found


def gate(lead: list[str], args: list[str], runtime: Runtime) -> int:
    """Runs `lead args` (`docker buildx bake`, with docker's options) if the definition it would build
    passes the policy for builds; returns 1 if it does not, otherwise docker replaces this process.
    """
    bake_policy = Scope(runtime).policy(runtime.cwd)
    if not verdict.screened(Report.of(check(runtime.docker, args, bake_policy, runtime.cwd))):
        return 1
    runtime.docker.exec([*lead, *args])


def check(docker: Docker, args: Sequence[str], bake_policy: policy.Policy, directory: str) -> list[Finding]:
    """Checks `bake` with these arguments, run in directory, by bake_policy.

    Returns why it may not run: refusals, or the failure to get the definition.
    """
    try:
        found = _definition(docker, args)
    except DockerError as e:
        hint = "fix the bake files, or use --print to see what docker makes of them"
        return [findings.failure_of(e, help=hint)]
    return bake_policy.check_bake(BakeDefinition(found, directory))
