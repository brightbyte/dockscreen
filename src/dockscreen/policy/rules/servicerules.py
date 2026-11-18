"""This module defines the ServiceRules class and the checks of each key (SERVICE_CHECKS), for judging the
keys of a service. The service is a compose service, or a container read back into compose service keys.

The lists name each key either as harmless (any value is fine) or as checked (it has an entry in
SERVICE_CHECKS that validates the value). The policy refuses a key that is neither, so a Compose feature that
Docker adds tomorrow stays denied until someone has reviewed it. Every check returns a list of human-readable
problems; an empty list means the value is acceptable.

In short, the rules protect against three kinds of service:
- one that gets root on the host through the kernel or the daemon (privileges, devices, host namespaces,
  another runtime);
- one that reads or writes host files (mounts, files read on the host, other containers' mounts);
- one that runs something unchecked beside its main process (hooks, develop.watch actions).

Each constant and check below names its threat and the defense against it.
"""

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Any

from dockscreen.policy.rules.base import (
    JudgedService,
    RuleBase,
    directory_of,
    is_inside,
    is_inside_any,
    unknown_key_problems,
)
from dockscreen.policy.rules.buildrules import BuildRules
from dockscreen.policy.rules.userrules import UserRules

if TYPE_CHECKING:
    from dockscreen.policy.policy import Policy

NO_NEW_PRIVILEGES = frozenset({"no-new-privileges", "no-new-privileges:true", "no-new-privileges=true"})

# What every service must have; hardening adds them where they are missing.
#
# cap_drop ALL: docker's default capability set lets a root process in the container override file
# permissions (CAP_DAC_OVERRIDE, CAP_FOWNER), change owners (CAP_CHOWN), switch to any id (CAP_SETUID,
# CAP_SETGID), create device nodes (CAP_MKNOD) and forge packets on the bridge network (CAP_NET_RAW). The
# user rules keep a service from running as root, but an image's setuid binary or a later bug could still
# make it root inside the container. Without capabilities, that root cannot use the bypasses on mounted
# files.
#
# no-new-privileges: the kernel ignores the setuid and setgid bits and file capabilities when the process
# executes a program. So a setuid-root binary that the image ships (sudo, su, or a binary made for the
# purpose) cannot turn the checked user into root. The user decision is only worth something with this set.
CAP_DROP = "ALL"
SECURITY_OPT = "no-new-privileges:true"

# Service keys that the policy refuses whenever they carry a value; harden removes them. Each is a way to
# root on the host or out of the project:
# - privileged: every capability and every device, and no seccomp or AppArmor profile; such a container
#   can mount the host's disks.
# - cap_add: single capabilities are enough to escape, e.g. CAP_SYS_ADMIN (mount, cgroup release agents),
#   CAP_DAC_READ_SEARCH (open_by_handle_at reads any host file, the "shocker" escape), CAP_SYS_PTRACE,
#   CAP_SYS_MODULE. cap_drop: [ALL] does not help, since docker applies cap_add after cap_drop.
# - devices, device_cgroup_rules: raw access to host devices, such as the disk under / (/dev/sda), and
#   the rules that let the container create and use such device nodes itself.
# - gpus: host devices, and the GPU runtime's hooks, which run on the host with the container's input.
# - cgroup_parent: puts the container in a cgroup of the host's choosing (system.slice, another
#   container's). There it is outside the limits that docker gives it, and it can starve the processes
#   there or share their resources.
# - external_links: links to containers outside the project. They are reachable by name, and older docker
#   copies their environment variables (passwords, tokens) into this container.
# - group_add: older docker daemons look a number up as a group name in the image's /etc/group first. So
#   an image with a group named "65534" whose gid is 0 gets gid 0. dockscreen can neither pin the value nor
#   read the group file for a service that sets user:.
FORBIDDEN_KEYS = (
    "privileged", "cap_add", "devices", "device_cgroup_rules", "gpus", "cgroup_parent", "external_links",
    "group_add",
)

# Namespaces that may not be the host's or another container's (`host`, `container:NAME`): - pid: the
# container sees and signals the host's processes, and reaches their files through /proc/PID/root and
# /proc/PID/cwd. - ipc: the host's System V and POSIX shared memory, which databases, X11 and audio servers
# use. - uts: the hostname; the host's own services and logs take it as theirs. - userns_mode: `host` turns
# off the daemon's user namespace remapping, where it is on, so root in the container is root on the host. -
# cgroup: the host's cgroup tree. - network_mode: the host's network reaches services that listen only on the
# host's 127.0.0.1 (a docker API on tcp, databases, local admin interfaces), and a container on it can bind
# the host's ports. Another container's network sees that container's traffic and its localhost. A tuple: the
# order of the checks is the order of the problems reported.
NAMESPACE_KEYS = ("pid", "ipc", "uts", "userns_mode", "cgroup", "network_mode")

# Service keys whose value cannot widen access beyond the container. Network exposure (ports, extra_hosts,
# dns, logging) is deliberately not restricted. Some keys are only harmless because of other rules:
# - sysctls can only set namespaced kernel settings, because docker refuses the others; those change the
#   host only in a host namespace, which the rules above refuse;
# - secrets and configs name the project's top-level secrets and configs, which the rules in ProjectRules
#   check;
# - tmpfs mounts memory, not host paths.
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

# Not sync+exec: its `exec` runs a command in the container with a user and a privileged flag of its own,
# as a hook does. That command is outside the checks of the service's user. (`exec` is not in WATCH_KEYS
# either.)
WATCH_ACTIONS = frozenset({"sync", "rebuild", "sync+restart"})
# The check _check_hooks judges the keys privileged and user; the other keys cannot widen access.
HOOK_KEYS = frozenset({"command", "user", "privileged", "working_dir", "environment"})
SELINUX_HINT = "; if bind mounts fail on SELinux, add the :z or :Z mount option instead"


class ServiceRules(RuleBase):
    """Mixin of Policy with the rules for the keys of a service, not used on its own."""

    def check_security_opt(self, value: Any, service: JudgedService) -> list[str]:
        """Checks security_opt. Returns the options that are not allowed, and a problem if no-new-privileges
        is missing.

        Allowed are no-new-privileges and the configured security_opts.

        Parameters:
        - value: the value of security_opt; None if it is missing
        - service: the service (JudgedService)
        """
        options = [str(o) for o in value or []]
        allowed_options = NO_NEW_PRIVILEGES | set(self.security_opts)
        problems = [f"security_opt {o!r} is not allowed{SELINUX_HINT if _is_selinux_label(o) else ''}"
                    for o in options if o not in allowed_options]
        if not has_no_new_privileges(options):
            problems.append(f"security_opt must include {SECURITY_OPT}")
        return problems

    def check_cap_drop(self, value: Any, service: JudgedService) -> list[str]:
        """Checks cap_drop; returns a problem unless it drops ALL.

        Parameters:
        - value: the value of cap_drop; None if it is missing
        - service: the service (JudgedService)
        """
        return [] if drops_all(value) else [f"cap_drop must include {CAP_DROP}"]

    def _check_runtime(self, value: Any, service: JudgedService) -> list[str]:
        """Checks runtime; returns a problem unless it is runc or unset.

        Any other runtime is a runtime that the daemon's configuration names. It may lack the isolation that
        runc gives (the GPU runtimes' host hooks, sysbox, a wrapper that an administrator added), or have an
        isolation that the other rules were not written for.
        """
        return [] if value in (None, "", "runc") else [f"runtime {value!r} is not allowed"]

    def _check_volumes_from(self, value: Any, service: JudgedService) -> list[str]:
        """Checks volumes_from; returns a problem for each source that is a container, not a service.

        A container outside the project can have any mounts that its creator chose. Taking its volumes also
        takes its bind mounts of host paths. Another service of the project is fine, because the policy
        checks it like this service.
        """
        return [
            f"volumes_from {source!r} reaches a container outside the project"
            for source in value or []
            if str(source).startswith("container:")
        ]

    def _check_mounts(self, value: Any, service: JudgedService) -> list[str]:
        """Checks a service's volumes. Returns their unknown keys and types, and the bind mounts outside the
        mount roots.

        A bind mount gives the container the host path itself: to read, and to write unless it is read-only. A
        source outside the project is a project's way to ~/.ssh, /etc or the docker socket (which is root on
        the host). This compares the source after resolving symlinks (base.is_inside), because docker follows
        them: a link in the project that points to / is outside. Other types need no check here: the rules in
        ProjectRules check named volumes where the project defines them, tmpfs is memory, and an image mount
        holds another image's files.
        """
        problems = []
        for mount in value or []:
            problems += unknown_key_problems(mount, MOUNT_KEYS, "mount key")
            for mount_type, allowed_keys in MOUNT_SUBKEYS.items():
                problems += unknown_key_problems(mount.get(mount_type) or {}, allowed_keys,
                                                 f"mount {mount_type} key")
            kind = mount.get("type")
            if kind == "bind":
                if not is_inside_any(mount.get("source", ""), self.mount_roots(service.directory)):
                    problems.append(self._outside_problem(f"bind mount {mount.get('source')!r}",
                                                          service.directory))
            elif kind not in ("volume", "tmpfs", "image"):
                problems.append(f"mount type {kind!r} is not allowed")
        return problems

    def _check_develop(self, value: Any, service: JudgedService) -> list[str]:
        """Checks develop. Returns its unknown keys, and the watch rules that have a bad action or a path
        outside the project.

        `compose watch` copies the changes under a watch path into the container (sync). So a path outside
        the project would hand the container host files, such as ~/.aws, whenever they change.
        """
        value, directory = value or {}, directory_of(service)
        problems = unknown_key_problems(value, DEVELOP_KEYS, "develop key")
        for rule in value.get("watch") or []:
            problems += unknown_key_problems(rule, WATCH_KEYS, "develop.watch key")
            if rule.get("action") not in WATCH_ACTIONS:
                problems.append(f"develop.watch action {rule.get('action')!r} is not allowed")
            if not is_inside(rule.get("path", ""), directory):
                problems.append(f"develop.watch path {rule.get('path')!r} is outside {directory}")
        return problems

    def _check_deploy(self, value: Any, service: JudgedService) -> list[str]:
        """Checks deploy. Returns its unknown keys, and its reservations of host devices.

        A device reservation is another way to ask for GPUs and other host devices (see FORBIDDEN_KEYS).
        """
        value = value or {}
        problems = unknown_key_problems(value, DEPLOY_KEYS, "deploy key")
        reservations = (value.get("resources") or {}).get("reservations") or {}
        for key in ("devices", "generic_resources"):
            if reservations.get(key):
                problems.append(
                    f"deploy.resources.reservations.{key} grants host devices and is not allowed")
        return problems


# A check of one service key: it takes the Policy, the value and the service, and returns the problems.
Check = Callable[["Policy", Any, JudgedService], list[str]]


def _forbid(key: str) -> Check:
    """Returns a check that refuses key whenever it carries a value."""
    return lambda policy, value, service: [f"{key} is not allowed"] if value else []


def _check_namespace(key: str) -> Check:
    """Returns a check for the namespace key. The check refuses the host's namespace and the namespaces of
    other containers.
    """
    def check(policy: "Policy", value: Any, service: JudgedService) -> list[str]:
        text = str(value)
        if text == "host" or text.startswith("container:"):
            return [f"{key}: {text} shares a namespace outside the project"]
        return []
    return check


def _check_host_files(key: str) -> Check:
    """Returns a check for key (env_file or label_file). The check refuses files outside the project
    directory.

    Compose reads these files on the host, as the user, and puts their content into the container's
    environment or labels. So a project that names ~/.aws/credentials, or similar files of the user, gets
    their content into a container it controls. These keys only show up in the definition when dockscreen
    loads it without env resolution. With env resolution, compose inlines the content and loses the path.
    """
    def check(policy: "Policy", value: Any, service: JudgedService) -> list[str]:
        problems, directory = [], directory_of(service)
        for entry in [value] if isinstance(value, (str, dict)) else value or []:
            path = entry.get("path") if isinstance(entry, dict) else entry
            if path and not is_inside(path, directory):
                problems.append(f"{key} {path!r} is outside {directory}")
        return problems
    return check


def _check_hooks(key: str) -> Check:
    """Returns a check for the hook key (post_start or pre_stop). The check refuses hooks that escalate.

    A hook is a command that compose runs in the container with `docker exec`, with a user and a privileged
    flag of its own. So a hook could run as root, or with every capability, beside a main process whose user
    the policy checked. The check refuses hooks with unknown keys, privileged hooks, and hooks whose user
    Policy.check_user refuses (rules.userrules).
    """
    def check(policy: "Policy", value: Any, service: JudgedService) -> list[str]:
        problems = []
        for hook in value or []:
            problems += unknown_key_problems(hook, HOOK_KEYS, f"{key} key")
            if hook.get("privileged"):
                problems.append(f"{key} privileged is not allowed")
            # without a user of its own, the hook runs as the service's checked user
            if hook.get("user") is not None:
                problems += policy.check_user(hook["user"], service)
        return problems
    return check

SERVICE_CHECKS: dict[str, Check] = {
    "user": UserRules.check_user,
    "cap_drop": ServiceRules.check_cap_drop,
    "security_opt": ServiceRules.check_security_opt,
    **{key: _forbid(key) for key in FORBIDDEN_KEYS},
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


def _is_selinux_label(option: str) -> bool:
    """Tells whether a security_opt option sets an SELinux label."""
    return option.startswith(("label=", "label:"))


def has_no_new_privileges(options: Iterable[Any] | None) -> bool:
    """Tells whether security_opt options turn on no-new-privileges."""
    return any(str(o) in NO_NEW_PRIVILEGES for o in options or [])


def drops_all(cap_drop: Iterable[Any] | None) -> bool:
    """Tells whether a cap_drop value drops ALL capabilities."""
    return CAP_DROP in {str(c).upper() for c in cap_drop or []}  # docker reads capability names in any case
