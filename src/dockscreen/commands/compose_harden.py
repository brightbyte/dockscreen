"""This module implements `docker compose harden` (and `fix`), dockscreen's own command, which prints a
compose override that fixes what can be fixed.

`global_args` are the compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), which
select the project.

_fix_config removes or replaces only what has a safe automatic fix; checking the result with
policy.check_config reports what is left.

_render writes the difference between a config and its fixed copy as a compose override file. Compose
merges override lists by appending and cannot drop a key by omitting it, so removals use the `!reset` tag
and replaced lists use `!override`. Values are written as JSON, which is valid YAML.
"""

import copy
import json
import os
import re
import sys
from collections.abc import Iterable, Sequence
from typing import Any

from dockscreen.compose import composeproject, inspect, serviceusers
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import hardening, policy
from dockscreen.screen.findings import Finding, failure_of
from dockscreen.util import ids, messages
from dockscreen.util.messages import printable

# What fix puts into `user`: the caller's own ids, which dockscreen passes to compose (ids.py) and allows
# only with --allow-me. A literal would only fit the person who ran harden.
_USER_TEMPLATE = "${UID}:${GID}"

# Keys whose removal is a safe fix.
_REMOVABLE_SERVICE_KEYS = (*policy.FORBIDDEN_KEYS, "runtime", *policy.NAMESPACE_KEYS)


def harden(global_args: list[str], args: Sequence[str], runtime: Runtime, allow_me: bool = False) -> int:
    """Prints a compose override that fixes what can be fixed; exits with 1 if problems remain.

    The patch is relative to the merged config as dockscreen will run it, defaults
    included: only what is needed on top of them to pass the audit is written out,
    and one comment says what is added automatically. Mount sources outside the
    project become placeholders to edit; problems without a safe automatic fix are
    listed as comments. Images are pulled and built first, as `up` would, to see
    which services need a user of their own.

    A user that has to be set becomes `${UID}:${GID}`, the caller's own, so the result is checked as
    if --allow-me were given, and the patch says that it needs it.
    """
    try:
        project = composeproject.load_project(global_args, runtime, allow_me=True)
    except inspect.Refused as e:
        for refusal in e.findings:
            messages.notice(refusal)
        return 1
    except (inspect.InspectError, ValueError) as e:
        messages.notice(failure_of(e))
        return 1
    for refusal in policy.check_daemon(project.remote):
        messages.notice(refusal)
        return 1

    base, static = project.static(), project.static_ctx()
    fixed = _fix_config(base, static)
    # what the patch runs as, as compose would read it; compose interpolates the generated file and makes
    # its paths absolute, so ${UID} or ./ETC there would read back differently from what was checked
    resolved = _as_compose_reads(fixed, static)
    remaining = [f for f in policy.check_config(base.with_definition(resolved), static) if f.fatal]
    notes = [hardening.defaults_note()]
    if remaining:
        messages.notice("the images were not looked at because of the problems below: "
                        "nothing was pulled or built")
    else:
        remaining, notes = _fix_image_users(project, fixed, resolved, notes)

    sys.stdout.write(_render(base.definition, fixed, remaining, notes=notes))
    for problem in remaining:
        messages.notice(f"cannot fix automatically: {problem}")
    return 1 if remaining else 0


def _fix_image_users(project: composeproject.Compose, fixed: dict[str, Any], resolved: dict[str, Any],
                     notes: list[str]) -> tuple[list[Finding], list[str]]:
    """Sets a user in fixed on the services whose image chose one that is not acceptable.

    Returns (problems left, notes). resolved: fixed as it will run, which is what the images are looked at
    with.
    """
    with project.generated() as command:
        prepared = project.prepare(command(resolved), resolved)
    if not prepared.decisions:
        return prepared.report.reasons, notes  # nothing could be looked at: pulling or building failed
    remaining: list[Finding] = []
    for name, assessment in prepared.decisions.items():
        if assessment.failed:  # setting a user does not fix an image that could not be read
            remaining.append(serviceusers.decision_problem(name, assessment))
        elif assessment.refused:
            fixed["services"][name]["user"] = _USER_TEMPLATE
            notes.append(f"service {name}: image {assessment.image.reference} chose a user that is not "
                         "acceptable, so user is set explicitly")
    return remaining, notes


def _fix_config(project: Project, ctx: policy.Context) -> dict[str, Any]:
    """Returns a copy of the project's definition with the problems that have a mechanical fix fixed.

    Fixable: user/group, privileges, host namespaces, and bind mount sources outside the project, which
    become placeholder paths for the user to edit. Unknown keys, volumes, networks, secrets, build contexts
    and env files have no safe automatic fix; they stay and are reported by check_config on the result.
    """
    fixed = copy.deepcopy(project.definition)
    for original in project.services:
        service = fixed["services"][original.name]
        service_ctx = ctx.for_service(original.name, original.definition)
        from_image = original.origin_of("user") is Origin.IMAGE and not service.get("user")
        if not from_image and policy.check_user(service.get("user"), service_ctx, original):
            service["user"] = _USER_TEMPLATE
        if policy.check_security_opt(service.get("security_opt"), service_ctx, original):
            service["security_opt"] = [policy.SECURITY_OPT]
        if policy.check_cap_drop(service.get("cap_drop"), ctx, original):
            service["cap_drop"] = [policy.CAP_DROP]
        for key in _REMOVABLE_SERVICE_KEYS:
            service.pop(key, None)
        if "volumes_from" in service:
            service["volumes_from"] = [
                v for v in service["volumes_from"] if not str(v).startswith("container:")]
            if not service["volumes_from"]:
                del service["volumes_from"]
        if "volumes" in service:
            service["volumes"] = [_fix_mount(m, service_ctx) for m in service["volumes"]]
    return fixed


def _as_compose_reads(config: dict[str, Any], ctx: policy.Context) -> dict[str, Any]:
    """Returns a copy of config as compose reads the patch, for checking it: _USER_TEMPLATE becomes the
    caller's ids, and a relative placeholder mount source a path in the project directory.
    """
    resolved = copy.deepcopy(config)
    for service in resolved.get("services", {}).values():
        if service.get("user") == _USER_TEMPLATE:
            service["user"] = ids.format_user(ctx.ids.me)
        for mount in service.get("volumes", []):
            if mount.get("type") == "bind" and not os.path.isabs(mount["source"]):
                mount["source"] = os.path.join(ctx.project_dir, mount["source"].removeprefix("./"))
    return resolved


def _fix_mount(mount: dict[str, Any], ctx: policy.Context) -> dict[str, Any]:
    """Returns mount, with a bind source outside ctx's mount roots replaced by a placeholder to edit."""
    if mount.get("type") != "bind" or policy.is_inside_any(mount["source"], ctx.mount_roots):
        return mount
    return {**mount, "source": _placeholder_source(mount["source"], ctx.project_dir)}


def _placeholder_source(source: str, project_dir: str) -> str:
    """Returns a relative, upper-case stand-in for a source outside the project: /etc becomes ./ETC.

    The upper case keeps it from naming the same directory as a real lower-case one, and marks it as
    something to edit.
    """
    relative = os.path.relpath(source, project_dir)
    if relative.startswith(os.pardir):
        relative = source.lstrip(os.sep)
    return "./" + relative.replace(os.sep, "_").upper()


_HEADER = "# Generated by `dockscreen harden`. Save as compose.override.yaml, or load it last with -f."
_SAFE_YAML_KEY = re.compile(r"^[A-Za-z0-9_.-]+$")


def _render(original: dict[str, Any], fixed: dict[str, Any], unfixed: Iterable[str] = (),
           notes: Iterable[str] = ()) -> str:
    """Renders the compose override that turns original into fixed, as YAML text.

    original: the config the patch is applied to, as it will be run (defaults included).
    unfixed and notes become comments.
    """
    lines = [_HEADER]
    lines += [f"# note: {printable(note)}" for note in notes]
    lines += [f"# edit: {printable(note)}" for note in _mount_notes(original, fixed)]
    lines += [f"# not fixed: {printable(problem)}" for problem in unfixed]

    changes = _service_changes(original, fixed)
    if any("user" in service for service in changes.values()):
        lines.append("# note: user ${UID}:${GID} runs a service as you: dockscreen allows that only with "
                     "--allow-me, and plain docker compose needs UID and GID exported.")
    if not changes:
        return "\n".join([*lines, "services: {}", ""])

    lines.append("services:")
    for name, service in changes.items():
        lines.append(f"  {json.dumps(name)}:")
        lines += [f"    {_yaml_key(key)}: {value}" for key, value in service.items()]
    return "\n".join([*lines, ""])


def _yaml_key(key: str) -> str:
    """Returns key as a YAML mapping key, quoted unless it is plainly safe."""
    return key if _SAFE_YAML_KEY.match(key) else json.dumps(key)


def _mount_notes(original: dict[str, Any], fixed: dict[str, Any]) -> list[str]:
    """Returns one note per mount whose source fixed replaced by a placeholder."""
    notes = []
    for name, before in original.get("services", {}).items():
        after = fixed["services"][name]
        for old, new in zip(before.get("volumes", []), after.get("volumes", [])):
            if old.get("source") != new.get("source"):
                notes.append(
                    f"service {name}: mount source {old['source']} was replaced by the placeholder "
                    f"{new['source']}, which compose creates empty; point it at a path inside the project")
    return notes


def _service_changes(original: dict[str, Any], fixed: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Returns {service: {key: rendered YAML value}} for the keys that fixed changes in original."""
    changes = {}
    for name, before in original.get("services", {}).items():
        after = fixed["services"][name]
        service = {
            key: _render_value(after.get(key))
            for key in sorted(set(before) | set(after))
            if before.get(key) != after.get(key)
        }
        if service:
            changes[name] = service
    return changes


def _render_value(value: Any) -> str:
    """Renders value as YAML for the override file, tagged so that it replaces what the project set."""
    if value is None:
        return "!reset null"
    if isinstance(value, list):
        return "!override " + json.dumps(value)
    return json.dumps(value)
