"""This module defines the BuildRules class, the group of the policy's rules for judging builds: a compose
service's `build:` and the targets of `docker buildx bake`, which share what a build may reach on this host
(BuildRules.check_build).

A build runs the project's Dockerfile, which is untrusted, on this host. Its RUN steps run in a sandbox,
but the build's inputs reach into them: the context and named contexts (COPY reads them, so a
context of / or ~ puts host files into an image the project controls), the network (the host's reaches
services on its localhost), the SSH agent (which authenticates as the caller to anything the agent's keys
open), privileges and entitlements (a privileged RUN is root on the host), secrets, and outputs and caches
(which write files on the host). The rules keep each of these inside the project or turn it off.
"""

import os
from collections.abc import Sequence
from typing import Any

from dockscreen.model.imagebuild import BakeDefinition, ImageBuild, fields
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding
from dockscreen.policy.rules.base import JudgedService, RuleBase, directory_of, is_inside, unknown_keys

# secrets names the project's top-level secrets, which ProjectRules checks where they are defined.
BUILD_HARMLESS_KEYS = frozenset({
    "args", "dockerfile_inline", "extra_hosts", "isolation", "labels", "no_cache", "platforms",
    "provenance", "pull", "sbom", "secrets", "shm_size", "tags", "target", "ulimits",
})

BUILD_KEYS = BUILD_HARMLESS_KEYS | {
    "context", "dockerfile", "additional_contexts", "network", "privileged", "ssh",
}
BAKE_TOP_LEVEL_KEYS = frozenset({"group", "target"})
BAKE_TARGET_KEYS = frozenset({
    "context", "contexts", "dockerfile", "dockerfile-inline", "args", "labels", "tags", "target",
    "platforms", "pull", "no-cache", "no-cache-filter", "annotations", "attest", "call", "shm-size",
    "ulimits", "output", "cache-from", "cache-to", "secret", "ssh", "network", "entitlements",
})

# Outputs that stay in the image store or a registry; the others write files to the host.
BAKE_OUTPUT_TYPES = frozenset({"image", "registry", "docker", "cacheonly"})
BAKE_CACHE_TO_TYPES = frozenset({"inline", "registry"})


class BuildRules(RuleBase):
    """Mixin of Policy with the rules for builds of images, not used on its own."""

    def _check_build(self, value: Any, service: JudgedService) -> list[str]:
        """Checks a service's build; returns unknown keys, sources outside the project, and escapes from
        it.
        """
        build = ImageBuild.from_compose(value, directory_of(service))
        # No extension fields here: `docker buildx bake` reads `x-bake` from compose files, and it can
        # set outputs and cache destinations on the host. Compose's own build does not pass it on.
        problems = unknown_keys(build.definition, BUILD_KEYS, "build key", extensions=False)
        problems += self.check_build(build, "build ")
        if build.definition.get("privileged"):  # RUN steps with every capability: root on the host
            problems.append("build privileged is not allowed")
        return problems

    def check_build(self, build: ImageBuild, prefix: str = "") -> list[str]:
        """Checks what a build reaches on this host, however it is defined; returns the problems: its
        context, Dockerfile and named contexts outside its directory, a network, and the SSH agent.

        Only sources that are paths on this host are checked, not URLs or services, which are fetched rather
        than read from this host. A Dockerfile outside the context is held to the directory too, so that
        everything the build reads from this host is the project's.

        Parameters:
        - build: the build (ImageBuild)
        - prefix: before each key in the problems
        """
        context_key, dockerfile_key, contexts_key = build.keys
        directory = build.directory
        problems = []
        context, dockerfile = build.context, build.dockerfile
        if context and _is_host_path(context):
            if not is_inside(context, directory):
                problems.append(f"{prefix}{context_key} {context!r} is outside {directory}")
            # a relative dockerfile is read from the context, not the project directory
            elif dockerfile and not is_inside(os.path.join(context, dockerfile), directory):
                problems.append(f"{prefix}{dockerfile_key} {dockerfile!r} is outside {directory}")
        for name, source in build.contexts.items():
            if _is_host_path(source) and not is_inside(str(source), directory):
                problems.append(f"{prefix}{contexts_key} {name!r}: {source!r} is outside {directory}")
        network = build.definition.get("network")
        if network not in (None, "", "none"):
            problems.append(f"{prefix}network {network!r} is not allowed")
        if build.definition.get("ssh"):
            problems.append(f"{prefix}ssh forwards your SSH agent and is not allowed")
        return problems

    def check_bake(self, bake: BakeDefinition) -> list[Finding]:
        """Checks what `docker buildx bake` would build; returns the refusals, each about its target."""
        problems = unknown_keys(bake.definition, BAKE_TOP_LEVEL_KEYS, "key", extensions=False)
        for name, build in bake.targets.items():
            problems += [f"target {name}: {p}" for p in self._check_bake_target(build)]
        return finding.refusals(problems)

    def _check_bake_target(self, build: ImageBuild) -> list[str]:
        """Returns the problems with a bake target: unknown keys, what it reaches (check_build), and what
        it writes to or reads from the host besides.
        """
        target = build.definition
        problems = unknown_keys(target, BAKE_TARGET_KEYS, "key", extensions=False)
        problems += self.check_build(build)
        # security.insecure (privileged RUN steps), network.host, device: the access a build sandbox exists
        # to deny
        if target.get("entitlements"):
            problems.append("entitlements ask for access beyond the build sandbox and are not allowed")
        problems += _check_outputs(target.get("output") or [], target.get("cache-to") or [])
        problems += self._check_cache_from(target.get("cache-from") or [], build.directory)
        problems += self._check_build_secrets(target.get("secret") or [], build.directory)
        return problems

    def _check_cache_from(self, entries: Sequence[Any], directory: str) -> list[str]:
        """Returns the problems with cache-from entries: unreadable ones, and local caches outside
        directory, which the build would read from the host like a context.
        """
        problems = []
        for entry in entries:
            found = fields(entry)
            if found is None:
                problems.append(f"cache-from {entry!r} cannot be read")
            elif found.get("type") == "local" and not is_inside(found.get("src", ""), directory):
                problems.append(f"cache-from {entry!r} is outside {directory}")
        return problems

    def _check_build_secrets(self, secrets: Sequence[Any], directory: str) -> list[str]:
        """Returns the problems with bake secret entries: variables instead of files, and files outside
        directory.

        A secret is readable by the RUN steps that mount it, which the project writes: a file outside the
        project (~/.ssh/id_ed25519) or a variable of the caller's (`env=AWS_SECRET_ACCESS_KEY`) can be copied
        into a layer or sent off.
        """
        problems = []
        for entry in secrets:
            found = fields(entry)
            source = (found or {}).get("src") or (found or {}).get("source")  # buildx takes either name
            if source is None:
                problems.append(f"secret {entry!r} copies a variable or cannot be read, and is not allowed")
            elif not is_inside(source, directory):
                problems.append(f"secret {entry!r} is outside {directory}")
        return problems


def _check_outputs(outputs: Sequence[Any], cache_to: Sequence[Any]) -> list[str]:
    """Returns the problems with a bake target's output and cache-to entries: any that write to the host.

    A local or tar output writes the build result to the project's choice of `dest`, as the caller: over
    ~/.bashrc, into ~/.ssh. Outputs that stay in the image store or go to a registry write nothing here.
    """
    problems = []
    for entry in outputs:
        found = fields(entry)
        # a bare path is a local directory
        if found is None or found.get("type") not in BAKE_OUTPUT_TYPES or "dest" in found:
            problems.append(f"output {entry!r} writes to the host and is not allowed")
    for entry in cache_to:
        found = fields(entry)
        if found is None or found.get("type") not in BAKE_CACHE_TO_TYPES:
            problems.append(f"cache-to {entry!r} writes to the host or an unknown store and is not allowed")
    return problems


def _is_host_path(source: Any) -> bool:
    """Tells whether a build source is a path on this host, not a URL (`git://`, ...) or a service."""
    text = str(source)
    return "://" not in text and not text.startswith("service:")
