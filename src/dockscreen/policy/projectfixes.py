"""This module provides the fixes of `docker compose harden`: a copy of a project's definition with what has a
safe automatic fix fixed, for the person to adopt as an override file.

Unlike hardening, which dockscreen applies to every run without changing the project, these change what
the project says, and only what the person writes back. What has no safe fix is left as it is, for
Policy.check_project to report on the result.
"""

import copy
import os
from collections.abc import Mapping
from typing import Any

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.policy import policy
from dockscreen.policy.finding import Finding
from dockscreen.policy.rules import servicerules
from dockscreen.policy.rules.base import is_inside_any
from dockscreen.policy.rules.userrules import image_problem
from dockscreen.policy.userdecision import UserDecision
from dockscreen.util import ids

# What fix puts into `user`: the caller's own ids, which dockscreen passes to compose (ids.py) and allows
# only with --allow-me. A literal would only fit the person who ran harden.
USER_TEMPLATE = "${UID}:${GID}"

# Keys whose removal is a safe fix.
_REMOVABLE_SERVICE_KEYS = (*servicerules.FORBIDDEN_KEYS, "runtime", *servicerules.NAMESPACE_KEYS)


def fixed_config(project: Project, pol: policy.Policy) -> dict[str, Any]:
    """Returns a copy of the project's definition with the problems that have a mechanical fix fixed.

    Fixable: user/group, privileges, host namespaces, and bind mount sources outside the project, which
    become placeholder paths for the user to edit. Unknown keys, volumes, networks, secrets, build contexts
    and env files have no safe automatic fix; they stay and are reported by Policy.check_project on the
    result.
    """
    fixed = copy.deepcopy(project.definition)
    for original in project.services:
        service = fixed["services"][original.name]
        service_pol = pol.for_service(original.name)
        from_image = original.origin_of("user") is Origin.IMAGE and not service.get("user")
        if not from_image and service_pol.check_user(service.get("user"), original):
            service["user"] = USER_TEMPLATE
        if service_pol.check_security_opt(service.get("security_opt"), original):
            service["security_opt"] = [servicerules.SECURITY_OPT]
        if service_pol.check_cap_drop(service.get("cap_drop"), original):
            service["cap_drop"] = [servicerules.CAP_DROP]
        for key in _REMOVABLE_SERVICE_KEYS:
            service.pop(key, None)
        if "volumes_from" in service:
            service["volumes_from"] = [
                v for v in service["volumes_from"] if not str(v).startswith("container:")]
            if not service["volumes_from"]:
                del service["volumes_from"]
        if "volumes" in service:
            service["volumes"] = [_fix_mount(m, service_pol, project.directory) for m in service["volumes"]]
    return fixed


def as_compose_reads(config: dict[str, Any], pol: policy.Policy, directory: str) -> dict[str, Any]:
    """Returns a copy of config, of the project in directory, as compose reads the patch, for checking it:
    USER_TEMPLATE becomes the caller's ids, and a relative placeholder mount source a path in directory.
    """
    resolved = copy.deepcopy(config)
    for service in resolved.get("services", {}).values():
        if service.get("user") == USER_TEMPLATE:
            service["user"] = ids.format_user(pol.ids.me)
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind" and not os.path.isabs(mount["source"]):
                mount["source"] = os.path.join(directory, mount["source"].removeprefix("./"))
    return resolved


def _fix_mount(mount: dict[str, Any], pol: policy.Policy, directory: str) -> dict[str, Any]:
    """Returns mount, with a bind source outside pol's mount roots for a project in directory replaced by a
    placeholder to edit.
    """
    if mount.get("type") != "bind" or is_inside_any(mount["source"], pol.mount_roots(directory)):
        return mount
    return {**mount, "source": _placeholder_source(mount["source"], directory)}


def _placeholder_source(source: str, project_dir: str) -> str:
    """Returns a relative, upper-case stand-in for a source outside the project: /etc becomes ./ETC.

    The upper case keeps it from naming the same directory as a real lower-case one, and marks it as
    something to edit.
    """
    relative = os.path.relpath(source, project_dir)
    if relative.startswith(os.pardir):
        relative = source.lstrip(os.sep)
    return "./" + relative.replace(os.sep, "_").upper()


def set_image_users(fixed: dict[str, Any], decisions: Mapping[str, UserDecision]
                    ) -> tuple[list[Finding], list[str]]:
    """Sets a user in fixed, a project's fixed definition, on the services whose image chose one that is not
    acceptable; returns (problems left, notes on what was set).

    Parameters:
    - fixed: the definition, as fixed_config gives it; changed in place
    - decisions: the decisions on the images' users, by service, as the images were looked at with fixed
    """
    remaining: list[Finding] = []
    notes: list[str] = []
    for name, decision in decisions.items():
        if decision.failed:  # setting a user does not fix an image that could not be read
            remaining.append(image_problem(name, decision))
        elif decision.refused:
            fixed["services"][name]["user"] = USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image.reference} chose a user that is not "
                         "acceptable, so user is set explicitly")
    return remaining, notes
