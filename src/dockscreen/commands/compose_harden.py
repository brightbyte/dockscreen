"""This module implements `docker compose harden` (and `fix`), dockscreen's own command, which prints a
compose override that fixes what can be fixed.

The compose options before the subcommand (e.g. ["-f", "x.yml"]), which select the project, are the
lead_args of the command line.

_fix_config removes or replaces only what has a safe automatic fix; checking the result with
Policy.check_project reports what is left.

_render writes the difference between a config and its fixed copy as a compose override file. Compose
merges override lists by appending and cannot drop a key by omitting it, so removals use the `!reset` tag
and replaced lists use `!override`. Values are written as JSON, which is valid YAML.
"""

import copy
import json
import os
import re
import sys
from collections.abc import Iterable
from typing import Any

from dockscreen.commands import helptext
from dockscreen.compose import inspect, projectscreening
from dockscreen.host.dockerclient import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import hardening, policy
from dockscreen.screen.findings import Finding, failure_of
from dockscreen.screen.report import Report
from dockscreen.screen.rules import service as service_rules
from dockscreen.screen.rules.base import is_inside_any
from dockscreen.screen.rules.users import image_problem
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, ids, messages
from dockscreen.util.messages import printable

# What fix puts into `user`: the caller's own ids, which dockscreen passes to compose (ids.py) and allows
# only with --allow-me. A literal would only fit the person who ran harden.
_USER_TEMPLATE = "${UID}:${GID}"

# Keys whose removal is a safe fix.
_REMOVABLE_SERVICE_KEYS = (*service_rules.FORBIDDEN_KEYS, "runtime", *service_rules.NAMESPACE_KEYS)


def harden(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Prints a compose override that fixes what can be fixed; exits with 1 if problems remain.

    The patch is relative to the merged config as dockscreen will run it, defaults
    included: only what is needed on top of them to pass the audit is written out,
    and one comment says what is added automatically. Mount sources outside the
    project become placeholders to edit; problems without a safe automatic fix are
    listed as comments. Images are pulled and built first, as `up` would, to see
    which services need a user of their own.

    A user that has to be set becomes `${UID}:${GID}`, the caller's own, so the result is checked as
    if --allow-me were given, and the patch says that it needs it.

    Parameters:
    - parent_cli: the compose command line, with `harden` or `fix` as its command; --allow-me in it makes no
      difference, since the result is checked as if it were given either way
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd in ("harden", "fix")
    try:
        loaded = projectscreening.load_project(list(parent_cli.lead_args), runtime)
    except inspect.ProjectRefused as e:
        for refusal in e.findings:
            messages.notice(refusal)
        return 1
    except (DockerError, ValueError) as e:
        messages.notice(failure_of(e))
        return 1
    screener = Screener(runtime, allow_me=True)
    static = screener.project_policy(loaded.resolved)
    for refusal in static.check_daemon(loaded.remote):
        messages.notice(refusal)
        return 1

    base = loaded.static()
    fixed = _fix_config(base, static)
    # what the patch runs as, as compose would read it; compose interpolates the generated file and makes
    # its paths absolute, so ${UID} or ./ETC there would read back differently from what was checked
    resolved = _as_compose_reads(fixed, static, base.directory)
    # the patched project goes through the same stages as `up` would take it through
    cleared = projectscreening.check(loaded.with_hardened(resolved), screener)
    notes = [hardening.defaults_note()]
    if isinstance(cleared, Report):
        remaining = list(cleared.findings)
        messages.notice("the images were not looked at because of the problems below: "
                        "nothing was pulled or built")
    else:
        remaining, notes = _fix_image_users(cleared, screener, fixed, notes)

    sys.stdout.write(_render(base.definition, fixed, remaining, notes=notes))
    for problem in remaining:
        messages.notice(f"cannot fix automatically: {problem}")
    return 1 if remaining else 0


def _fix_image_users(cleared: projectscreening.ClearedProject, screener: Screener, fixed: dict[str, Any],
                     notes: list[str]) -> tuple[list[Finding], list[str]]:
    """Sets a user in fixed on the services whose image chose one that is not acceptable.

    Returns (problems left, notes). cleared: the project with fixed as it will run, which is what the images
    are looked at with.
    """
    with cleared.loaded.generated(screener.docker.binary) as command:
        decided = projectscreening.decide(cleared, screener, command)
    if not decided.decisions:
        return list(decided.report.findings), notes  # nothing could be looked at: pulling or building failed
    remaining: list[Finding] = []
    for name, decision in decided.decisions.items():
        if decision.failed:  # setting a user does not fix an image that could not be read
            remaining.append(image_problem(name, decision))
        elif decision.refused:
            fixed["services"][name]["user"] = _USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image.reference} chose a user that is not "
                         "acceptable, so user is set explicitly")
    return remaining, notes


def _fix_config(project: Project, pol: policy.Policy) -> dict[str, Any]:
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
            service["user"] = _USER_TEMPLATE
        if service_pol.check_security_opt(service.get("security_opt"), original):
            service["security_opt"] = [service_rules.SECURITY_OPT]
        if service_pol.check_cap_drop(service.get("cap_drop"), original):
            service["cap_drop"] = [service_rules.CAP_DROP]
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


def _as_compose_reads(config: dict[str, Any], pol: policy.Policy, directory: str) -> dict[str, Any]:
    """Returns a copy of config, of the project in directory, as compose reads the patch, for checking it:
    _USER_TEMPLATE becomes the caller's ids, and a relative placeholder mount source a path in directory.
    """
    resolved = copy.deepcopy(config)
    for service in resolved.get("services", {}).values():
        if service.get("user") == _USER_TEMPLATE:
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


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name, from the docstring of harden.

    Parameters:
    - name: the command, as the dispatcher knows it: harden, or its alias fix
    """
    return helptext.command_topic("harden", harden, aliases=("fix",))
