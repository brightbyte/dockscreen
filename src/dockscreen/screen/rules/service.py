"""This module defines the policy's rules for the keys of a service, which a compose service and a container
read back into compose service keys alike are judged by (SERVICE_CHECKS).

A key is listed either as harmless (any value is fine) or as checked (it has an entry in SERVICE_CHECKS
that validates the value). A key that is neither is refused, so a Compose feature added tomorrow is
denied until someone has reviewed it. Every check returns a list of human-readable problems; an empty list
means the value is acceptable.
"""

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from dockscreen.screen.rules.base import (
    RuleBase,
    Subject,
    directory_of,
    is_inside,
    is_inside_any,
    unknown_keys,
)
from dockscreen.screen.rules.build import BuildRules
from dockscreen.util import ids

if TYPE_CHECKING:
    from dockscreen.screen.policy import Policy

NO_NEW_PRIVILEGES = frozenset({"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"})

# What every service must have; hardening adds them where they are missing.
CAP_DROP = "ALL"
SECURITY_OPT = "no-new-privileges:true"

# Service keys that are refused whenever they carry a value; harden removes them. group_add is one
# because older docker daemons look a number up as a group name in the image's /etc/group first, and
# dockscreen can neither pin the value nor read the group file for every service.
FORBIDDEN_KEYS = (
    "privileged", "cap_add", "devices", "device_cgroup_rules", "gpus", "cgroup_parent", "external_links",
    "group_add",
)

# A tuple: the order of the checks is the order of the problems reported.
NAMESPACE_KEYS = ("pid", "ipc", "uts", "userns_mode", "cgroup", "network_mode")

# Service keys whose value cannot widen access beyond the container. Network
# exposure (ports, extra_hosts, dns, logging) is deliberately not restricted.
HARMLESS_SERVICE_KEYS = frozenset({
    "annotations", "attach", "blkio_config", "command", "configs", "container_name", "cpu_count",
    "cpu_percent", "cpu_period", "cpu_quota", "cpu_rt_period", "cpu_rt_runtime", "cpu_shares", "cpus",
    "cpuset", "depends_on", "dns", "dns_opt", "dns_search", "domainname", "entrypoint", "environment",
    "expose", "extra_hosts", "healthcheck", "hostname", "image", "init", "isolation", "labels", "links",
    "logging", "mac_address", "mem_limit", "mem_reservation", "mem_swappiness", "memswap_limit",
    "networks", "oom_kill_disable", "oom_score_adj", "pids_limit", "platform", "ports", "profiles",
    "pull_policy", "read_only", "restart", "scale", "secrets", "shm_size", "stdin_open",
    "stop_grace_period", "stop_signal", "storage_opt", "sysctls", "tmpfs", "tty", "ulimits",
    "working_dir",
})

# Keys that must be present: a missing value is a problem in itself.
REQUIRED_SERVICE_KEYS = frozenset({"user", "security_opt", "cap_drop"})
MOUNT_KEYS = frozenset({
    "type", "source", "target", "read_only", "consistency", "bind", "volume", "tmpfs", "image",
})

MOUNT_SUBKEYS = {
    "bind": frozenset({"propagation", "create_host_path", "selinux", "recursive"}),
    "volume": frozenset({"nocopy", "subpath"}),
    "tmpfs": frozenset({"size", "mode"}),
    "image": frozenset({"subpath"}),
}
DEPLOY_KEYS = frozenset({
    "mode", "replicas", "labels", "update_config", "rollback_config", "restart_policy", "resources",
    "placement", "endpoint_mode",
})

DEVELOP_KEYS = frozenset({"watch"})
WATCH_KEYS = frozenset({"path", "action", "target", "ignore", "include", "initial_sync"})

# Not sync+exec: it runs a command in the container.
WATCH_ACTIONS = frozenset({"sync", "rebuild", "sync+restart"})
HOOK_KEYS = frozenset({"command", "user", "privileged", "working_dir", "environment"})
SELINUX_HINT = "; if bind mounts fail on SELinux, add the :z or :Z mount option instead"


class ServiceRules(RuleBase):
    """Rules for the keys of a service."""

    def check_user(self, value: Any, service: Subject) -> list[str]:
        """Checks a `user:` of service as hardening left it; returns the problems, empty for an acceptable
        `uid:gid`.

        Refused are a missing user, a name (hardening resolved those that exist), a missing group, and ids
        the id rules refuse (ids, with whether service reaches host files and the configured user allowed).
        """
        if not value:
            return ["user is not set, the image default may be root"]
        user, has_group, group = str(value).partition(":")
        uid, gid = ids.parse_id(user), ids.parse_id(group)
        if uid is None:
            return [_not_a_name("user", user)]
        if not has_group:
            # docker would take the group, and supplementary groups, from the image
            return [f"user {value!r} has no group, use uid:gid"]
        if gid is None:
            return [_not_a_name("group", group)]
        configured = (self.configured_user,) if self.configured_user else ()
        return [f"user {value!r}: {p}"
                for p in self.ids.problems(uid, gid, mounts=service.reaches_host, extra=configured)]

    def check_security_opt(self, value: Any, service: Subject) -> list[str]:
        """Checks security_opt; returns its options that are not allowed, and no-new-privileges if missing.

        Allowed are no-new-privileges and the configured security_opts.
        """
        options = [str(o) for o in value or []]
        allowed = NO_NEW_PRIVILEGES | set(self.security_opts)
        problems = [f"security_opt {o!r} is not allowed{SELINUX_HINT if _is_selinux_label(o) else ''}"
                    for o in options if o not in allowed]
        if not has_no_new_privileges(options):
            problems.append(f"security_opt must include {SECURITY_OPT}")
        return problems

    def check_cap_drop(self, value: Any, service: Subject) -> list[str]:
        """Checks cap_drop; returns a problem unless it drops ALL."""
        return [] if drops_all(value) else [f"cap_drop must include {CAP_DROP}"]

    def _check_runtime(self, value: Any, service: Subject) -> list[str]:
        """Checks runtime; returns a problem unless it is runc or unset."""
        return [] if value in (None, "", "runc") else [f"runtime {value!r} is not allowed"]

    def _check_volumes_from(self, value: Any, service: Subject) -> list[str]:
        """Checks volumes_from; returns a problem for each source that is a container, not a service."""
        return [
            f"volumes_from {source!r} reaches a container outside the project"
            for source in value or []
            if str(source).startswith("container:")
        ]

    def _check_mounts(self, value: Any, service: Subject) -> list[str]:
        """Checks a service's volumes; returns their unknown keys and types, and bind mounts outside the
        mount roots.
        """
        problems = []
        for mount in value or []:
            problems += unknown_keys(mount, MOUNT_KEYS, "mount key")
            for sub, allowed in MOUNT_SUBKEYS.items():
                problems += unknown_keys(mount.get(sub) or {}, allowed, f"mount {sub} key")
            kind = mount.get("type")
            if kind == "bind":
                if not is_inside_any(mount.get("source", ""), self.mount_roots(service.directory)):
                    problems.append(self._outside(f"bind mount {mount.get('source')!r}", service.directory))
            elif kind not in ("volume", "tmpfs", "image"):
                problems.append(f"mount type {kind!r} is not allowed")
        return problems

    def _check_develop(self, value: Any, service: Subject) -> list[str]:
        """Checks develop; returns unknown keys, and watch rules with bad actions or paths outside the
        project.
        """
        value, directory = value or {}, directory_of(service)
        problems = unknown_keys(value, DEVELOP_KEYS, "develop key")
        for rule in value.get("watch") or []:
            problems += unknown_keys(rule, WATCH_KEYS, "develop.watch key")
            if rule.get("action") not in WATCH_ACTIONS:
                problems.append(f"develop.watch action {rule.get('action')!r} is not allowed")
            if not is_inside(rule.get("path", ""), directory):
                problems.append(f"develop.watch path {rule.get('path')!r} is outside {directory}")
        return problems

    def _check_deploy(self, value: Any, service: Subject) -> list[str]:
        """Checks deploy; returns unknown keys, and reservations of host devices."""
        value = value or {}
        problems = unknown_keys(value, DEPLOY_KEYS, "deploy key")
        reservations = (value.get("resources") or {}).get("reservations") or {}
        for key in ("devices", "generic_resources"):
            if reservations.get(key):
                problems.append(
                    f"deploy.resources.reservations.{key} grants host devices and is not allowed")
        return problems


# A check of one service key: takes the Policy, the value and the service, returns the problems.
Check = Callable[["Policy", Any, Subject], list[str]]


def _forbidden(key: str) -> Check:
    """Returns a check that refuses key whenever it carries a value."""
    return lambda policy, value, service: [f"{key} is not allowed"] if value else []


def _check_namespace(key: str) -> Check:
    """Returns a check for the namespace key that refuses the host's namespace and other containers'."""
    def check(policy: "Policy", value: Any, service: Subject) -> list[str]:
        text = str(value)
        if text == "host" or text.startswith("container:"):
            return [f"{key}: {text} shares a namespace outside the project"]
        return []
    return check


def _check_host_files(key: str) -> Check:
    """Returns a check for key (env_file or label_file) that refuses files outside the project directory.

    These keys only show up in the definition when it is loaded without env resolution.
    """
    def check(policy: "Policy", value: Any, service: Subject) -> list[str]:
        problems, directory = [], directory_of(service)
        for entry in [value] if isinstance(value, (str, dict)) else value or []:
            path = entry.get("path") if isinstance(entry, dict) else entry
            if path and not is_inside(path, directory):
                problems.append(f"{key} {path!r} is outside {directory}")
        return problems
    return check


def _check_hooks(key: str) -> Check:
    """Returns a check for the hook key (post_start or pre_stop) that refuses hooks that escalate.

    Those are hooks with unknown keys, privileged ones, and ones whose user Policy.check_user refuses.
    """
    def check(policy: "Policy", value: Any, service: Subject) -> list[str]:
        problems = []
        for hook in value or []:
            problems += unknown_keys(hook, HOOK_KEYS, f"{key} key")
            if hook.get("privileged"):
                problems.append(f"{key} privileged is not allowed")
            if hook.get("user") is not None:  # without one, the hook runs as the service's checked user
                problems += policy.check_user(hook["user"], service)
        return problems
    return check

SERVICE_CHECKS: dict[str, Check] = {
    "user": ServiceRules.check_user,
    "cap_drop": ServiceRules.check_cap_drop,
    "security_opt": ServiceRules.check_security_opt,
    **{key: _forbidden(key) for key in FORBIDDEN_KEYS},
    "runtime": ServiceRules._check_runtime,
    **{key: _check_namespace(key) for key in NAMESPACE_KEYS},
    "volumes": ServiceRules._check_mounts,
    "volumes_from": ServiceRules._check_volumes_from,
    "build": BuildRules._check_build,
    "env_file": _check_host_files("env_file"),
    "label_file": _check_host_files("label_file"),
    "develop": ServiceRules._check_develop,
    "deploy": ServiceRules._check_deploy,
    "post_start": _check_hooks("post_start"),
    "pre_stop": _check_hooks("pre_stop"),
}


def _not_a_name(kind: str, value: str) -> str:
    """Returns the problem with a user or group (kind) value that is still a name after hardening.

    Hardening resolves every name that exists on this host, so this one does not.
    """
    return (f"{kind} {value!r} does not exist on this host (names are resolved on this host, "
            "never in the image)")


def _is_selinux_label(option: str) -> bool:
    """Tells whether a security_opt option sets an SELinux label."""
    return option.startswith(("label=", "label:"))


def has_no_new_privileges(options: Iterable[Any] | None) -> bool:
    """Tells whether security_opt options turn on no-new-privileges."""
    return any(str(o) in NO_NEW_PRIVILEGES for o in options or [])


def drops_all(cap_drop: Iterable[Any] | None) -> bool:
    """Tells whether a cap_drop value drops ALL capabilities."""
    return CAP_DROP in {str(c).upper() for c in cap_drop or []}  # docker reads capability names in any case
