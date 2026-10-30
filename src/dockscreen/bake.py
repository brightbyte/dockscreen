"""`docker buildx bake`: what the bake files of the project let the builds reach on this host.

Bake reads files the project controls (docker-bake.hcl, compose files with `x-bake`), as `compose build`
does, so the same things are refused: build sources outside the project, host networking, the SSH
agent. Bake adds ways to write to the host (`output`, `cache-to`) and to read files and variables
(`secret`).

`docker buildx bake --print` gives the definition that would be built, with the command line applied
(`--set`, `--push`, targets), and builds nothing. It is screened as such: a key that is not known is
refused, because a new one may be a new way out.
"""
import csv
import json
import os

from dockscreen import messages, policy
from dockscreen.dockerclient import DockerError

TOP_LEVEL_KEYS = frozenset({"group", "target"})
TARGET_KEYS = frozenset({
    "context", "contexts", "dockerfile", "dockerfile-inline", "args", "labels", "tags", "target",
    "platforms", "pull", "no-cache", "no-cache-filter", "annotations", "attest", "call", "shm-size",
    "ulimits", "output", "cache-from", "cache-to", "secret", "ssh", "network", "entitlements",
})
# Outputs that stay in the image store or a registry; the others write files to the host.
OUTPUT_TYPES = frozenset({"image", "registry", "docker", "cacheonly"})
CACHE_TO_TYPES = frozenset({"inline", "registry"})
NOT_SCREENED = {"--print", "--help", "-h"}  # builds nothing


def wants_screening(args):
    """Whether `bake` with these arguments builds, and so needs screening."""
    return not NOT_SCREENED & set(args)


def definition(docker, args):
    """The bake definition for the arguments (a dict), or raise DockerError with why not."""
    result = docker.capture([docker.binary, "buildx", "bake", "--print", *args])
    if result.returncode != 0:
        raise DockerError(result.stderr.strip() or "docker buildx bake --print failed")
    try:
        found = json.loads(result.stdout)
    except ValueError as e:
        raise DockerError(f"cannot read the bake definition: {e}") from e
    if not isinstance(found, dict):
        raise DockerError("cannot read the bake definition: not an object")
    return found


def check_definition(found, project_dir):
    """Why the definition may not be built, as a list of problems."""
    problems = policy.unknown_keys(found, TOP_LEVEL_KEYS, "key", extensions=False)
    for name, target in (found.get("target") or {}).items():
        problems += [f"target {name}: {p}" for p in _check_target(target or {}, project_dir)]
    return problems


def _check_target(target, project_dir):
    """Problems with a bake target: unknown keys, sources outside project_dir, access beyond the build."""
    problems = policy.unknown_keys(target, TARGET_KEYS, "key", extensions=False)
    problems += policy.check_build_sources(target, project_dir, ("context", "dockerfile", "contexts"))
    if target.get("network") not in (None, "", "none"):
        problems.append(f"network {target['network']!r} is not allowed")
    if target.get("entitlements"):
        problems.append("entitlements ask for access beyond the build sandbox and are not allowed")
    if target.get("ssh"):
        problems.append("ssh forwards your SSH agent and is not allowed")
    problems += _check_outputs(target.get("output") or [], target.get("cache-to") or [])
    problems += _check_cache_from(target.get("cache-from") or [], project_dir)
    problems += _check_secrets(target.get("secret") or [], project_dir)
    return problems


def _fields(entry):
    """{key: value} of a `key=value,key=value` entry, or None if it is not that. A bare word has no keys."""
    try:
        parts = next(csv.reader([str(entry)]), [])
    except csv.Error:
        return None
    pairs = [part.partition("=") for part in parts]
    return {key.strip(): value for key, equals, value in pairs if equals}


def _check_outputs(outputs, cache_to):
    """Problems with a target's output and cache-to entries: any that write to the host."""
    problems = []
    for entry in outputs:
        found = _fields(entry)
        # a bare path is a local directory
        if found is None or found.get("type") not in OUTPUT_TYPES or "dest" in found:
            problems.append(f"output {entry!r} writes to the host and is not allowed")
    for entry in cache_to:
        found = _fields(entry)
        if found is None or found.get("type") not in CACHE_TO_TYPES:
            problems.append(f"cache-to {entry!r} writes to the host or an unknown store and is not allowed")
    return problems


def _check_cache_from(entries, project_dir):
    """Problems with cache-from entries: a local cache outside project_dir, or one that cannot be read."""
    problems = []
    for entry in entries:
        found = _fields(entry)
        if found is None:
            problems.append(f"cache-from {entry!r} cannot be read")
        elif found.get("type") == "local" and not policy.is_inside(found.get("src", ""), project_dir):
            problems.append(f"cache-from {entry!r} is outside {project_dir}")
    return problems


def _check_secrets(secrets, project_dir):
    """Problems with secret entries: a variable instead of a file, or a file outside project_dir."""
    problems = []
    for entry in secrets:
        found = _fields(entry)
        source = (found or {}).get("src") or (found or {}).get("source")
        if source is None:
            problems.append(f"secret {entry!r} copies a variable or cannot be read, and is not allowed")
        elif not policy.is_inside(source, project_dir):
            problems.append(f"secret {entry!r} is outside {project_dir}")
    return problems


def screen(docker, args):
    """(reasons, failed): why `bake` with these arguments may not run, and whether that is a failure to look."""
    try:
        found = definition(docker, args)
    except DockerError as e:
        hint = "fix the bake files, or use --print to see what docker makes of them"
        return [messages.Reason(str(e), hint)], True
    return check_definition(found, os.getcwd()), False
