"""This module defines the BuildRules class, the group of the policy's rules for judging builds: a compose
service's `build:` and the targets of `docker buildx bake`. Both share the rules on what a build may reach
on this host (BuildRules.check_build).

A build runs the project's Dockerfile, which is untrusted, on this host. Its RUN steps run in a sandbox,
but the build's inputs reach into them:
- the context and named contexts: COPY reads them, so a context of / or ~ puts host files into an image
  that the project controls;
- the network: the host's network reaches services on its localhost;
- the SSH agent, which authenticates as the user to anything that the agent's keys open;
- privileges and entitlements: a privileged RUN step is root on the host;
- secrets;
- outputs and caches, which write files on the host.

The rules keep each of these inside the project, or turn it off.
"""

import os
from collections.abc import Sequence
from typing import Any

from dockscreen.model.imagebuild import BakeDefinition, ImageBuild, fields
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding
from dockscreen.policy.rules.base import (
    JudgedService,
    RuleBase,
    directory_of,
    is_inside,
    unknown_key_problems,
)

# secrets names the project's top-level secrets. The rules in ProjectRules check those secrets where the
# project defines them.
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
        """Checks a service's build. Returns its unknown keys, its sources outside the project, and the ways
        it escapes the project.
        """
        build = ImageBuild.from_compose(value, directory_of(service))
        # No extension fields here: `docker buildx bake` reads `x-bake` from compose files, and `x-bake` can
        # set outputs and cache destinations on the host. Compose's own build does not pass it on.
        problems = unknown_key_problems(build.definition, BUILD_KEYS, "build key", allows_extensions=False)
        problems += self.check_build(build, "build ")
        if build.definition.get("privileged"):  # RUN steps with every capability: root on the host
            problems.append("build privileged is not allowed")
        return problems

    def check_build(self, build: ImageBuild, prefix: str = "") -> list[str]:
        """Checks the parts of this host that a build reaches, however the build is defined. Returns the
        problems: a context, Dockerfile or named context outside the build's directory, a network, and the
        SSH agent.

        This checks only sources that are paths on this host. It does not check URLs or services, because the
        builder fetches those instead of reading them from this host. A Dockerfile outside the context must
        be inside the directory too, so that everything the build reads from this host is the project's.

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
        problems = unknown_key_problems(bake.definition, BAKE_TOP_LEVEL_KEYS, "key", allows_extensions=False)
        for name, build in bake.targets.items():
            problems += [f"target {name}: {p}" for p in self._check_bake_target(build)]
        return finding.refusals(problems)

    def _check_bake_target(self, build: ImageBuild) -> list[str]:
        """Returns the problems with a bake target: its unknown keys, the parts of the host it reaches
        (check_build), and any other files on the host that it writes or reads.
        """
        target = build.definition
        problems = unknown_key_problems(target, BAKE_TARGET_KEYS, "key", allows_extensions=False)
        problems += self.check_build(build)
        # security.insecure (privileged RUN steps), network.host and device grant the access that a build
        # sandbox exists to deny
        if target.get("entitlements"):
            problems.append("entitlements ask for access beyond the build sandbox and are not allowed")
        problems += _check_outputs(target.get("output") or [], target.get("cache-to") or [])
        problems += self._check_cache_from(target.get("cache-from") or [], build.directory)
        problems += self._check_build_secrets(target.get("secret") or [], build.directory)
        return problems

    def _check_cache_from(self, entries: Sequence[Any], directory: str) -> list[str]:
        """Returns the problems with cache-from entries: entries that this function cannot read, and local
        caches outside directory. The build would read such a cache from the host, like a context.
        """
        problems = []
        for entry in entries:
            entry_fields = fields(entry)
            if entry_fields is None:
                problems.append(f"cache-from {entry!r} cannot be read")
            elif (entry_fields.get("type") == "local"
                  and not is_inside(entry_fields.get("src", ""), directory)):
                problems.append(f"cache-from {entry!r} is outside {directory}")
        return problems

    def _check_build_secrets(self, secrets: Sequence[Any], directory: str) -> list[str]:
        """Returns the problems with bake secret entries: variables instead of files, and files outside
        directory.

        The RUN steps that mount a secret can read it, and the project writes those steps. So a file outside
        the project (~/.ssh/id_ed25519), or a variable of the user's (`env=AWS_SECRET_ACCESS_KEY`), is a
        secret that the project's RUN steps can copy into a layer or send off.
        """
        problems = []
        for entry in secrets:
            entry_fields = fields(entry)
            # buildx takes either name
            source = (entry_fields or {}).get("src") or (entry_fields or {}).get("source")
            if source is None:
                problems.append(f"secret {entry!r} copies a variable or cannot be read, and is not allowed")
            elif not is_inside(source, directory):
                problems.append(f"secret {entry!r} is outside {directory}")
        return problems


def _check_outputs(outputs: Sequence[Any], cache_to: Sequence[Any]) -> list[str]:
    """Returns the problems with a bake target's output and cache-to entries: any that write to the host.

    A local or tar output writes the build result, as the user, to a `dest` of the project's choice: over
    ~/.bashrc, or into ~/.ssh. Outputs that stay in the image store or go to a registry write nothing here.
    """
    problems = []
    for entry in outputs:
        entry_fields = fields(entry)
        # a bare path is a local directory
        if (entry_fields is None or entry_fields.get("type") not in BAKE_OUTPUT_TYPES
            or "dest" in entry_fields):
            problems.append(f"output {entry!r} writes to the host and is not allowed")
    for entry in cache_to:
        entry_fields = fields(entry)
        if entry_fields is None or entry_fields.get("type") not in BAKE_CACHE_TO_TYPES:
            problems.append(f"cache-to {entry!r} writes to the host or an unknown store and is not allowed")
    return problems


def _is_host_path(source: Any) -> bool:
    """Tells whether a build source is a path on this host, not a URL (`git://`, ...) or a service."""
    text = str(source)
    return "://" not in text and not text.startswith("service:")
