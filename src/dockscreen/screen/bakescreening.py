"""This module provides functions for screening what `docker buildx bake` would build.

`docker buildx bake --print` gives the definition bake would build, with the command line applied
(`--set`, `--push`, targets), and builds nothing. The policy judges that definition as it is
(Policy.check_bake), and refuses a key it does not know, because a new key may be a new way out.

Bake needs screening for two reasons. `docker buildx bake` reads docker-bake.hcl, or `x-bake` in a compose
file, from the current directory, so the project decides the build. And bake has powers that compose's
builds cannot be given: it can write outputs and caches to host paths, mount the SSH agent and secrets from
files or variables, and ask for entitlements such as privileged RUN steps. Bake files are HCL, with variables,
functions and the command line's `--set`; dockscreen uses bake's own `--print` instead of a parser of
its own, so that the policy judges bake's own definition.
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

    Returns the reasons it may not run: refusals, or the failure to get the definition.

    Parameters:
    - docker: the docker to run bake with
    - bake: buildx's part of the command line, with `bake` as its command
    - bake_policy: the policy for builds
    - directory: the directory bake runs in; bake's relative paths are relative to it
    """
    try:
        definition = _definition(docker, bake)
    except DockerError as e:
        hint = "fix the bake files, or use --print to see what docker makes of them"
        return [finding.failure_of(e, help=hint)]
    return bake_policy.check_bake(BakeDefinition(definition, directory))


def _definition(docker: Docker, bake: commandline.CommandLine) -> dict[str, Any]:
    """Returns the bake definition for the command line, as `--print` gives it, without building anything.

    dockscreen asks for it with the options before `buildx` and `bake`, which choose the daemon and the
    builder.

    Raises DockerError, with the reason, if docker cannot give a definition or the definition is not a JSON
    object.
    """
    result = docker.capture([docker.binary, *bake.global_args, "bake", "--print", *bake.args])
    if result.returncode != 0:
        raise DockerError("docker buildx bake --print failed", result.stderr.strip())
    try:
        definition = json.loads(result.stdout)
    except ValueError as e:
        raise DockerError(f"cannot read the bake definition: {e}") from e
    if not isinstance(definition, dict):
        raise DockerError("cannot read the bake definition: not an object")
    return definition
