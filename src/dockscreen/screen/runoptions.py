"""This module provides functions for turning the options of `docker compose run` into substitutions on the
service it runs, with the command line as their origin, so that the policy can judge the service as it will
run.

Compose applies these options to the service itself, from the command line, after reading the project:
`--user` replaces the service's user; `-v` adds a mount; `--cap-add` and `--cap-drop` each add to their own
list, and take the same capabilities out of the other list; `--env-from-file` reads a file on this host,
like an env_file. The other options of `run` set keys that the policy does not restrict.

Compose reads a `-v` source as a bind mount if it starts with `.`, `/` or `~`, and as a named volume
otherwise. Compose leaves the source as it is. The policy judges `~` as the home directory, and a relative
source against the project directory, so that the judged source reaches at least as far as the source that
can run. An `--env-from-file` path is read from the current directory.
"""

import os
from collections.abc import Sequence
from typing import Any

from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import Origin
from dockscreen.model.project import Service
from dockscreen.policy.projectpatch import ProjectPatch, Substitution
from dockscreen.screen import userargs

USER = ("--user", "-u")
VOLUME = ("--volume", "-v")
ENV_FILE = ("--env-from-file",)


def substitutions(user_args: userargs.UserArgs[str], service: Service, runtime: Runtime) -> ProjectPatch:
    """Returns the patch that turns service into the service that `run` runs with the options of user_args.

    Parameters:
    - user_args: the arguments of `run`
    - service: the service that `run` runs
    - runtime: the Runtime of the command; relative paths are read from its current directory, and `~`
      stands for its home directory
    """
    substitutions = []
    definition = service.definition
    if users := _values(user_args, USER):
        substitutions.append(_set(service, "user", users[-1]))  # the last one wins, as in docker
    if mounts := [_mount(spec, runtime.home) for spec in _values(user_args, VOLUME)]:
        substitutions.append(_set(service, "volumes", [*(definition.get("volumes") or []), *mounts]))
    if env_files := [os.path.join(runtime.cwd, path) for path in _values(user_args, ENV_FILE)]:
        substitutions.append(_set(service, "env_file", [*_to_list(definition.get("env_file")), *env_files]))
    added_capabilities = _values(user_args, ("--cap-add",))
    dropped_capabilities = _values(user_args, ("--cap-drop",))
    cap_add, cap_drop = _capabilities(definition, added_capabilities, dropped_capabilities)
    if cap_add != list(definition.get("cap_add") or []):
        substitutions.append(_set(service, "cap_add", cap_add))
    if cap_drop != list(definition.get("cap_drop") or []):
        substitutions.append(_set(service, "cap_drop", cap_drop))
    return ProjectPatch.of(substitutions)


def _values(user_args: userargs.UserArgs[str], options: Sequence[str]) -> list[str]:
    """Returns the values user_args gives to any of options, in their order."""
    return [value for option, value in user_args.values if option in options]


def _set(service: Service, key: str, value: Any) -> Substitution:
    """Returns the substitution that sets key of service to value, from the command line."""
    return Substitution(service.name, key, value, origin=Origin.COMMAND_LINE)


def _capabilities(definition: dict[str, Any], added_capabilities: list[str],
                  dropped_capabilities: list[str]) -> tuple[list, list]:
    """Returns (cap_add, cap_drop) of the service with definition, once compose applies --cap-add
    (added_capabilities) and --cap-drop (dropped_capabilities). Compose appends each capability to its own
    list and takes it out of the other list, added_capabilities first.
    """
    cap_add, cap_drop = list(definition.get("cap_add") or []), list(definition.get("cap_drop") or [])
    if added_capabilities:
        cap_add = [*cap_add, *added_capabilities]
        cap_drop = [c for c in cap_drop if c not in added_capabilities]
    if dropped_capabilities:
        cap_drop = [*cap_drop, *dropped_capabilities]
        cap_add = [c for c in cap_add if c not in dropped_capabilities]
    return cap_add, cap_drop


def _mount(spec: str, home: str) -> dict[str, Any]:
    """Returns the mount, in compose's long syntax, that a `-v` spec adds.

    A spec with more parts than source, target and options gets no type, and the policy refuses such a
    mount.
    """
    parts = spec.split(":")
    if len(parts) == 1:
        return {"type": "volume", "target": spec}  # an anonymous volume
    if len(parts) > 3:
        return {"source": spec}
    source, target, *options = parts
    if not source.startswith((".", "/", "~")):
        return {"type": "volume", "source": source, "target": target}
    if source.startswith("~"):
        source = home + source[1:]
    mount: dict[str, Any] = {"type": "bind", "source": source, "target": target}
    if "ro" in (options[0].split(",") if options else []):
        mount["read_only"] = True
    return mount


def _to_list(value: Any) -> list[Any]:
    """Returns an env_file value as a list of its entries."""
    if value is None:
        return []
    return [value] if isinstance(value, (str, dict)) else list(value)
