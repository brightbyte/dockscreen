"""This module provides functions for screening what `docker buildx bake` would build.

`docker buildx bake --print` gives the definition that would be built, with the command line applied
(`--set`, `--push`, targets), and builds nothing. The policy judges it as such (Policy.check_bake): a key
that is not known is refused, because a new one may be a new way out.
"""

import json
from typing import Any

from dockscreen.host.docker import Docker, DockerError
from dockscreen.model.imagebuild import BakeDefinition
from dockscreen.policy import finding, policy
from dockscreen.policy.finding import Finding
from dockscreen.util import commandline


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
        return [finding.failure_of(e, help=hint)]
    return bake_policy.check_bake(BakeDefinition(found, directory))


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
