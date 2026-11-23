"""This module provides functions for finding the shell variables that end up in each service of a compose
project, and for the ids that dockscreen passes to compose.

dockscreen passes UID and GID, the real ids of the invoking user, in the environment of the compose
commands it runs, so that compose files can interpolate them (`user: "${UID}:${GID}"`). They override
values already in the environment. That way, `${UID}` is the invoking user's real uid, which --allow-me
allows, and not the value of an inherited variable. The policy refuses these ids unless the invoking user
gives --allow-me (see rules.idrules); passing them only makes the project's intent readable.

`environment: [FOO]` takes FOO from the shell. The resolved config shows FOO like any other value, so the
function copied_shell_variables recognises a pass-through by its value: the value equals the shell's value
of the variable with the same name. This test also catches `FOO: bar` when the shell happens to have
FOO=bar, and it misses `X: ${FOO}`, which copies the value under another name. The function leaves out the
variables that dockscreen passes to compose (EXPORTED_VARIABLES). The policy judges the result
(Policy.check_shell_env).
"""

from collections.abc import Mapping
from typing import Any

EXPORTED_VARIABLES = ("UID", "GID")


def exported_variables(me: tuple[int, int]) -> dict[str, str]:
    """Returns the variables UID and GID for me.

    Parameters:
    - me: the invoking user's real (uid, gid)
    """
    return dict(zip(EXPORTED_VARIABLES, (str(i) for i in me)))


def copied_shell_variables(config: dict[str, Any], env: Mapping[str, str]) -> dict[str, list[str]]:
    """Returns {service: [variable names]}: the variables in each service's environment whose value is the
    shell's own.

    Parameters:
    - config: the project's resolved definition
    - env: the shell's environment
    """
    names_by_service = {}
    for name, service in sorted((config.get("services") or {}).items()):
        environment = (service or {}).get("environment")
        if not isinstance(environment, dict):
            continue
        names = sorted(
            key for key, value in environment.items()
            if value and key not in EXPORTED_VARIABLES and env.get(key) == value
        )
        if names:
            names_by_service[name] = names
    return names_by_service

