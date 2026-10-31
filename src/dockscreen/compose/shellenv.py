"""Which environment variables of the shell end up in which service, and the ids dockscreen adds.

dockscreen passes UID and GID, the real ids of the caller, in the environment of the compose commands
it runs, for compose files to interpolate (`user: "${UID}:${GID}"`); values already in the environment
are overridden. Running as these ids is not allowed unless --allow-me is given (see idrules): passing
them only makes the project's intent readable.

`environment: [FOO]` takes FOO from the shell. The resolved config shows it like any other value, so a
pass-through is recognised by the value being the shell's own under the same name. That also catches
`FOO: bar` when the shell happens to have FOO=bar, and misses `X: ${FOO}`, which copies the value under
another name. The variables dockscreen passes to compose (EXPORTED) are left out. Values are never shown.
"""

from collections.abc import Mapping
from typing import Any

from dockscreen import messages

EXPORTED = ("UID", "GID")


def exported(me: tuple[int, int]) -> dict[str, str]:
    """Returns the variables UID and GID for me, the caller's real (uid, gid)."""
    return dict(zip(EXPORTED, (str(i) for i in me)))


def _copied(config: dict[str, Any], env: Mapping[str, str]) -> dict[str, list[str]]:
    """Returns {service: [variable names]} for the environment values of services that are the shell's own."""
    found = {}
    for name, service in sorted((config.get("services") or {}).items()):
        environment = (service or {}).get("environment")
        if not isinstance(environment, dict):
            continue
        names = sorted(
            key for key, value in environment.items()
            if value and key not in EXPORTED and env.get(key) == value
        )
        if names:
            found[name] = names
    return found


def describe(config: dict[str, Any], env: Mapping[str, str]) -> list[messages.Marked]:
    """Returns one warning per service that gets variables from the shell (env)."""
    return [
        messages.Marked(
            messages.WARN, f"service {name}: environment variables taken from your shell: {', '.join(names)}",
            "unset them in your shell, or give the project literal values, to keep them out")
        for name, names in _copied(config, env).items()
    ]
