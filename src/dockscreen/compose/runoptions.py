"""This module provides functions for turning the options of `docker compose run` into substitutions on the
service it runs, with the command line as their origin, so that the service can be judged as it will run.

Compose applies these options to the service itself, from the command line, after reading the project:
`--user` replaces the service's user; `-v` adds a mount; `--cap-add` and `--cap-drop` add to theirs and
take the same capabilities out of the other; `--env-from-file` reads a file on this host, like an
env_file. The other options of `run` set keys that the policy does not restrict.

A `-v` source is a bind mount if it starts with `.`, `/` or `~`, else a named volume, as compose reads it.
Compose leaves the source as it is; `~` is judged as the home directory and a relative source against
the project directory, so that what is judged reaches at least as far as what can run. An
`--env-from-file` path is read from the current directory.
"""

import os
from collections.abc import Sequence
from typing import Any

from dockscreen.cli import userargs
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import Origin
from dockscreen.model.project import Service
from dockscreen.screen.substitutions import Substitution

USER = ("--user", "-u")
VOLUME = ("--volume", "-v")
ENV_FILE = ("--env-from-file",)


def substitutions(parsed: userargs.Parsed, service: Service, runtime: Runtime) -> list[Substitution]:
    """Returns the substitutions that make service what `run` with parsed's options runs, from runtime's
    current directory, with its home directory as `~`.
    """
    found = []
    definition = service.definition
    if users := _values(parsed, USER):
        found.append(_set(service, "user", users[-1]))  # the last one wins, as in docker
    if mounts := [_mount(spec, runtime.home) for spec in _values(parsed, VOLUME)]:
        found.append(_set(service, "volumes", [*(definition.get("volumes") or []), *mounts]))
    if env_files := [os.path.join(runtime.cwd, path) for path in _values(parsed, ENV_FILE)]:
        found.append(_set(service, "env_file", [*_as_list(definition.get("env_file")), *env_files]))
    added, dropped = _values(parsed, ("--cap-add",)), _values(parsed, ("--cap-drop",))
    cap_add, cap_drop = _capabilities(definition, added, dropped)
    if cap_add != list(definition.get("cap_add") or []):
        found.append(_set(service, "cap_add", cap_add))
    if cap_drop != list(definition.get("cap_drop") or []):
        found.append(_set(service, "cap_drop", cap_drop))
    return found


def _values(parsed: userargs.Parsed, options: Sequence[str]) -> list[str]:
    """Returns the values parsed gives to any of options, in their order."""
    return [value for option, value in parsed.users.values if option in options]


def _set(service: Service, key: str, value: Any) -> Substitution:
    """Returns the substitution that sets key of service to value, from the command line."""
    return Substitution(service.name, key, value, origin=Origin.COMMAND_LINE)


def _capabilities(definition: dict[str, Any], added: list[str], dropped: list[str]) -> tuple[list, list]:
    """Returns (cap_add, cap_drop) of the service with definition once compose applies --cap-add (added)
    and --cap-drop (dropped): each is appended to its own list and taken out of the other, added first.
    """
    cap_add, cap_drop = list(definition.get("cap_add") or []), list(definition.get("cap_drop") or [])
    if added:
        cap_add = [*cap_add, *added]
        cap_drop = [c for c in cap_drop if c not in added]
    if dropped:
        cap_drop = [*cap_drop, *dropped]
        cap_add = [c for c in cap_add if c not in dropped]
    return cap_add, cap_drop


def _mount(spec: str, home: str) -> dict[str, Any]:
    """Returns the mount, in compose's long syntax, that a `-v` spec adds.

    A spec with more parts than source, target and options gets no type, which the policy refuses.
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


def _as_list(value: Any) -> list[Any]:
    """Returns an env_file value as a list of its entries."""
    if value is None:
        return []
    return [value] if isinstance(value, (str, dict)) else list(value)
