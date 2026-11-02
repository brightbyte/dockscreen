"""This module defines the security policy for services, written as compose service keys, and for what they
can reach.

Services come from two places. A compose project's come from its definition (`docker compose config
--format json`), which Policy.check_project judges as a whole: services, and the volumes, networks,
secrets and configs they use. A container that `docker run` created is read back into the service keys
of the same meaning (container.Container.definition) and judged by Policy.check_container. Builds, from
compose or bake, are judged by the build checks.

The policy is an allowlist and fails closed: a key that is not listed below is
refused, so a Compose feature added tomorrow is denied until someone has
reviewed it. Every structure that can carry unlisted keys (service, mount,
build, volume, network, secret, deploy, develop, hooks) has its own list. Keys
beginning with `x-` are extension fields that Compose itself ignores; they pass
everywhere except in `build` (see Policy._check_build).

A key is listed either as harmless (any value is fine) or as checked (it has an
entry in SERVICE_CHECKS that validates the value). A Policy holds the settings the
rules apply with, such as the id rules (idrules.Rules) that decide which uids and gids
a project may choose; what is known about the thing judged belongs to it, not to the
policy. Every rule is a method of Policy, whether it reads the settings or not.

Every check of a key returns a list of human-readable problems; an empty list means
the value is acceptable. The checks of a whole project or container turn them into
findings (findings.Finding) about the service, volume or network they concern. Nothing
here touches docker, only the filesystem for realpath resolution.
"""

import os
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from typing import Any, NamedTuple, Protocol, Self

from dockscreen.host import config as configuration
from dockscreen.model.build import BakeDefinition, Build, fields
from dockscreen.model.container import Container
from dockscreen.model.identity import Identity
from dockscreen.model.image import Inspected
from dockscreen.model.location import Location
from dockscreen.model.mounts import BIND_FLAGS, mount_flags
from dockscreen.model.origin import TRUSTED, Origin
from dockscreen.model.project import Project
from dockscreen.screen import idrules, imageuser
from dockscreen.screen.assessment import Assessment, Kind
from dockscreen.screen.findings import Finding, Severity, about, judged, refused
from dockscreen.util import ids

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

# Volume driver_opts types that stay on this host's filesystem or memory.
LOCAL_VOLUME_TYPES = frozenset({"", "none", "tmpfs"})
VOLUME_DRIVER_OPTS = frozenset({"type", "device", "o"})
NETWORK_DRIVERS = frozenset({None, "", "bridge", "none"})
NETWORK_DRIVER_OPTS = frozenset({"com.docker.network.driver.mtu"})

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

TOP_LEVEL_KEYS = frozenset({"name", "services", "volumes", "networks", "secrets", "configs", "version"})
VOLUME_KEYS = frozenset({"name", "driver", "driver_opts", "external", "labels"})
NETWORK_KEYS = frozenset({
    "name", "driver", "driver_opts", "external", "internal", "attachable", "enable_ipv4", "enable_ipv6",
    "ipam", "labels",
})
IPAM_KEYS = frozenset({"driver", "config", "options"})
SECRET_KEYS = frozenset({"name", "file", "environment", "content", "external", "labels"})
MOUNT_KEYS = frozenset({
    "type", "source", "target", "read_only", "consistency", "bind", "volume", "tmpfs", "image",
})
MOUNT_SUBKEYS = {
    "bind": frozenset({"propagation", "create_host_path", "selinux", "recursive"}),
    "volume": frozenset({"nocopy", "subpath"}),
    "tmpfs": frozenset({"size", "mode"}),
    "image": frozenset({"subpath"}),
}
BUILD_HARMLESS_KEYS = frozenset({
    "args", "dockerfile_inline", "extra_hosts", "isolation", "labels", "no_cache", "platforms",
    "provenance", "pull", "sbom", "secrets", "shm_size", "tags", "target", "ulimits",
})
BUILD_KEYS = BUILD_HARMLESS_KEYS | {
    "context", "dockerfile", "additional_contexts", "network", "privileged", "ssh",
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

BAKE_TOP_LEVEL_KEYS = frozenset({"group", "target"})
BAKE_TARGET_KEYS = frozenset({
    "context", "contexts", "dockerfile", "dockerfile-inline", "args", "labels", "tags", "target",
    "platforms", "pull", "no-cache", "no-cache-filter", "annotations", "attest", "call", "shm-size",
    "ulimits", "output", "cache-from", "cache-to", "secret", "ssh", "network", "entitlements",
})
# Outputs that stay in the image store or a registry; the others write files to the host.
BAKE_OUTPUT_TYPES = frozenset({"image", "registry", "docker", "cacheonly"})
BAKE_CACHE_TO_TYPES = frozenset({"inline", "registry"})



class Subject(Protocol):
    """Service as Policy.check_service judges it: one of a compose project (project.Service), or what a
    container asks for, read back as one (container.Container).
    """

    @property
    def definition(self) -> dict[str, Any]:
        """Returns its compose service keys."""
        ...

    @property
    def reaches_host(self) -> bool:
        """Tells whether it reaches host files (mounts.service_reaches_host)."""
        ...

    def origin_of(self, key: str) -> Origin:
        """Returns where the value of key comes from."""
        ...


class UserOption(NamedTuple):
    """User a command line gives: --user with its value, or --as with the name and the account of that name
    on this host (None: there is none).
    """
    flag: str
    value: str
    account: tuple[int, int] | None = None


# The ways to choose a user on a docker command line, named in refusals of --user.
USER_OPTION_ALTERNATIVES = "; --as NAME runs as a local user, --as-me as yourself"
REMOTE_MESSAGE = "the daemon is not the default local one; ids and paths cannot be checked"
SELINUX_HINT = "; if bind mounts fail on SELinux, add the :z or :Z mount option instead"


class Policy(NamedTuple):
    """Security policy for the projects in one directory: the rules, and the settings they apply with (the
    project directory, the ids it may choose, and what else decides what a service may reach).
    """
    project_dir: str
    ids: idrules.Rules
    extra_dirs: tuple = ()  # mount_dirs from the config file
    # Whose values are taken as given: what the policy refuses in them is pointed out instead.
    trust: frozenset[Origin] = TRUSTED
    # The caller's config file, named in hints on what it can allow; no hints without it.
    config_file: str | None = None
    security_opts: tuple = ()  # allowed besides no-new-privileges (security_opts in the config file)
    # The user the config file sets for this service (its image's or project's, or the top level's):
    # its uid and gid are allowed ids for the service too, whoever names them.
    configured_user: tuple | None = None
    # What runs instead of an image that would run as root, and the HOME it gets (default_home).
    default_user: tuple[int, int] = configuration.Config().default_user
    default_home: str = configuration.Config().default_home
    # (name, service) -> this policy for that service, with the settings of its image section if one
    # applies; None if every service gets this one.
    per_service: Callable[[str, dict[str, Any]], "Policy"] | None = None

    @classmethod
    def for_settings(cls, settings: configuration.Config, project_dir: str, rules: idrules.Rules,
                     config_file: str | None = None) -> Self:
        """Returns the policy for a project in project_dir with these settings (config.effective).

        rules: the id rules with the caller's allow_me; the settings give them their nobody range and
        default user. config_file: named in hints, as in Policy.
        """
        return cls(project_dir, rules.with_settings(settings), settings.mount_dirs, config_file=config_file,
                   security_opts=settings.security_opts, configured_user=settings.user,
                   default_user=settings.default_user, default_home=settings.default_home)

    @property
    def mount_roots(self) -> tuple[str, ...]:
        """Returns where bind mounts may come from: the project directory, then the configured mount_dirs."""
        return (self.project_dir, *self.extra_dirs)

    def for_service(self, name: str, service: dict[str, Any]) -> "Policy":
        """Returns the policy to check the service called name with: per_service's for it, with this one's
        trust, else this one.
        """
        return self.per_service(name, service).with_trust(self.trust) if self.per_service else self

    def with_trust(self, trust: frozenset[Origin]) -> Self:
        """Returns this policy with trust as the origins whose values are taken as given."""
        return self._replace(trust=trust)

    def with_per_service(self, per_service: Callable[[str, dict[str, Any]], "Policy"]) -> Self:
        """Returns this policy with per_service giving the policy of each service (for_service)."""
        return self._replace(per_service=per_service)

    # --- projects, services and containers ---------------------------------------

    def check_project(self, project: Project) -> list[Finding]:
        """Checks what is known about a compose project: its definition, where it is, and, once they have
        been looked at, its daemon and the containers that have its name; returns what it finds, each about
        what it concerns.

        Empty if it passes. Each service is checked with its own policy (for_service).
        """
        config, name = project.definition, project.name
        problems = refused([*unknown_keys(config, TOP_LEVEL_KEYS, "top-level key"),
                            *_check_service_names(config)])
        if not name:  # volumes and networks are scoped to the project by its name
            problems += refused(["config has no project name"])
        for service in project.services:
            found = self.for_service(service.name, service.definition).check_service(service)
            problems += about(found, f"service {service.name}")
        for key, volume in project.volumes.items():
            problems += refused(self._check_volume(key, volume, name), f"volume {key}")
        for key, network in (config.get("networks") or {}).items():
            problems += refused(self._check_network(key, network, name), f"network {key}")
        problems += self._check_file_sources(config)
        problems += self.check_location(project.location)
        if project.remote is not None:
            problems += self.check_daemon(project.remote)
        if name and project.made_from is not None:
            problems += self.check_project_name(name, project.directory, project.made_from)
        return problems

    def check_project_build(self, project: Project) -> list[Finding]:
        """Checks a compose project against the part of the policy that applies to `build`; returns the
        refusals.

        That part is what building can reach on the host: names, build sections, secrets and configs.

        Runtime hardening (user, capabilities, mounts) is irrelevant until containers run.
        """
        problems = refused(_check_service_names(project.definition))
        for service in project.services:
            if "build" in service.definition:
                build = self._check_build(service.definition["build"], service)
                problems += refused(build, f"service {service.name}")
        return problems + self._check_file_sources(project.definition)  # build secrets refer to these

    def check_service(self, service: Subject) -> list[Finding]:
        """Checks one service; returns what it finds, empty if there is nothing.

        A problem is refused, or notable if its value comes from an origin that this policy trusts
        (findings.judged). A user from the image is left to the image decision.
        """
        keys = service.definition
        found = []
        for key in keys:
            unknown = unknown_keys({key: keys[key]}, HARMLESS_SERVICE_KEYS | SERVICE_CHECKS.keys(), "key")
            found += judged(unknown, service.origin_of(key), self.trust)
        for key, check in SERVICE_CHECKS.items():
            origin = service.origin_of(key)
            if key == "user" and origin is Origin.IMAGE:
                continue
            if key in REQUIRED_SERVICE_KEYS or key in keys:
                found += judged(check(self, keys.get(key), service), origin, self.trust)
        return found

    def check_container(self, container: Container) -> list[Finding]:
        """Checks what a container asks for as check_service would check a service that asked for the same
        (Container.definition); returns what it finds.

        Its keys come from the command line that created it, judged with the current directory as the
        project's; its user from where container.user_origin says.
        """
        return self.check_service(container)

    # --- images -------------------------------------------------------------------

    def needs_user_files(self, origin: Origin) -> bool:
        """Tells whether check_image needs the image's passwd and group files (Inspected.passwd) for a
        container whose user comes from origin: only to judge the image's own user, when the config file
        sets none for it.
        """
        return origin is Origin.IMAGE and not self.configured_user

    def check_image(self, inspected: Inspected, origin: Origin, match: configuration.Match) -> Assessment:
        """Decides which user the container that inspected looked through may run as, by the rules in
        imagedecision's docstring; returns the Assessment.

        origin: where the container's user comes from; one that is not the image's is not judged here
        (Kind.EXPLICIT). match: which image section of the config file applies to the image, which is
        this policy's. The passwd and group files must have been read if needs_user_files says so.
        """
        image = inspected.image
        notes = (Finding(match.problem, Severity.NOTABLE),) if match.problem else ()
        found: dict[str, Any] = {"section": match.repository}
        if origin is not Origin.IMAGE:
            return Assessment(Kind.EXPLICIT, image, notes, **found)
        if self.configured_user:
            return Assessment(Kind.CONFIGURED, image, notes, Identity(*self.configured_user),
                              user=self.configured_user, **found)
        assert inspected.passwd is not None and inspected.group is not None, "the user files were read"
        try:
            identity = imageuser.resolve(inspected.user, inspected.passwd, inspected.group)
        except ValueError as e:
            return Assessment(Kind.IMAGE, image, (*notes, Finding(str(e))), **found)
        if identity.involves_root:
            return Assessment(Kind.FALLBACK, image, notes, identity, user=self.default_user,
                              home=self.default_home, **found)
        problems = self.ids.problems(identity.uid, identity.gid, identity.supplementary,
                                     mounts=inspected.reaches_host)
        refusals = tuple(Finding(f"the image's {p}") for p in problems)
        return Assessment(Kind.IMAGE, image, (*notes, *refusals), identity,
                          user=(identity.uid, identity.gid), **found)

    # --- users and privileges -------------------------------------------------

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

    # --- mounts and files -----------------------------------------------------

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
                if not is_inside_any(mount.get("source", ""), self.mount_roots):
                    problems.append(self._outside(f"bind mount {mount.get('source')!r}"))
            elif kind not in ("volume", "tmpfs", "image"):
                problems.append(f"mount type {kind!r} is not allowed")
        return problems

    def _check_build(self, value: Any, service: Subject) -> list[str]:
        """Checks a service's build; returns unknown keys, sources outside the project, and escapes from
        it.
        """
        build = Build.from_compose(value)
        # No extension fields here: `docker buildx bake` reads `x-bake` from compose files, and it can
        # set outputs and cache destinations on the host. Compose's own build does not pass it on.
        problems = unknown_keys(build.definition, BUILD_KEYS, "build key", extensions=False)
        problems += self.check_build(build, "build ")
        if build.definition.get("privileged"):
            problems.append("build privileged is not allowed")
        return problems

    def check_build(self, build: Build, prefix: str = "") -> list[str]:
        """Checks what a build reaches on this host, however it is defined; returns the problems: its
        context, Dockerfile and named contexts outside the project directory, a network, and the SSH agent.

        Only sources that are paths on this host are checked, not URLs or services.
        prefix: before each key in the problems.
        """
        context_key, dockerfile_key, contexts_key = build.keys
        project_dir = self.project_dir
        problems = []
        context, dockerfile = build.context, build.dockerfile
        if context and _is_host_path(context):
            if not is_inside(context, project_dir):
                problems.append(f"{prefix}{context_key} {context!r} is outside {project_dir}")
            # a relative dockerfile is read from the context, not the project directory
            elif dockerfile and not is_inside(os.path.join(context, dockerfile), project_dir):
                problems.append(f"{prefix}{dockerfile_key} {dockerfile!r} is outside {project_dir}")
        for name, source in build.contexts.items():
            if _is_host_path(source) and not is_inside(str(source), project_dir):
                problems.append(f"{prefix}{contexts_key} {name!r}: {source!r} is outside {project_dir}")
        network = build.definition.get("network")
        if network not in (None, "", "none"):
            problems.append(f"{prefix}network {network!r} is not allowed")
        if build.definition.get("ssh"):
            problems.append(f"{prefix}ssh forwards your SSH agent and is not allowed")
        return problems

    # --- bake -----------------------------------------------------------------

    def check_bake(self, bake: BakeDefinition) -> list[Finding]:
        """Checks what `docker buildx bake` would build; returns the refusals, each about its target."""
        problems = unknown_keys(bake.definition, BAKE_TOP_LEVEL_KEYS, "key", extensions=False)
        for name, build in bake.targets.items():
            problems += [f"target {name}: {p}" for p in self._check_bake_target(build)]
        return refused(problems)

    def _check_bake_target(self, build: Build) -> list[str]:
        """Returns the problems with a bake target: unknown keys, what it reaches (check_build), and what
        it writes to or reads from the host besides.
        """
        target = build.definition
        problems = unknown_keys(target, BAKE_TARGET_KEYS, "key", extensions=False)
        problems += self.check_build(build)
        if target.get("entitlements"):
            problems.append("entitlements ask for access beyond the build sandbox and are not allowed")
        problems += _check_outputs(target.get("output") or [], target.get("cache-to") or [])
        problems += self._check_cache_from(target.get("cache-from") or [])
        problems += self._check_build_secrets(target.get("secret") or [])
        return problems

    def _check_cache_from(self, entries: Sequence[Any]) -> list[str]:
        """Returns the problems with cache-from entries: unreadable ones, and local caches outside the
        project.
        """
        problems = []
        for entry in entries:
            found = fields(entry)
            if found is None:
                problems.append(f"cache-from {entry!r} cannot be read")
            elif found.get("type") == "local" and not is_inside(found.get("src", ""), self.project_dir):
                problems.append(f"cache-from {entry!r} is outside {self.project_dir}")
        return problems

    def _check_build_secrets(self, secrets: Sequence[Any]) -> list[str]:
        """Returns the problems with bake secret entries: variables instead of files, and files outside the
        project.
        """
        problems = []
        for entry in secrets:
            found = fields(entry)
            source = (found or {}).get("src") or (found or {}).get("source")  # buildx takes either name
            if source is None:
                problems.append(f"secret {entry!r} copies a variable or cannot be read, and is not allowed")
            elif not is_inside(source, self.project_dir):
                problems.append(f"secret {entry!r} is outside {self.project_dir}")
        return problems

    # --- other structured keys ------------------------------------------------

    def _check_develop(self, value: Any, service: Subject) -> list[str]:
        """Checks develop; returns unknown keys, and watch rules with bad actions or paths outside the
        project.
        """
        value = value or {}
        problems = unknown_keys(value, DEVELOP_KEYS, "develop key")
        for rule in value.get("watch") or []:
            problems += unknown_keys(rule, WATCH_KEYS, "develop.watch key")
            if rule.get("action") not in WATCH_ACTIONS:
                problems.append(f"develop.watch action {rule.get('action')!r} is not allowed")
            if not is_inside(rule.get("path", ""), self.project_dir):
                problems.append(f"develop.watch path {rule.get('path')!r} is outside {self.project_dir}")
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

    # --- top-level volumes, networks, secrets ---------------------------------

    def _check_volume(self, key: str, volume: dict[str, Any] | None, project: str | None) -> list[str]:
        """Checks the top-level volume called key; returns problems with its keys, scope, driver,
        driver_opts.
        """
        volume = volume or {}
        problems = [*unknown_keys(volume, VOLUME_KEYS, "key"), *_check_scope(key, volume, project)]
        driver = volume.get("driver")
        if driver not in (None, "", "local"):
            return [*problems, f"driver {driver!r} is not allowed"]
        return [*problems, *self._check_driver_opts(volume.get("driver_opts") or {})]

    def _check_driver_opts(self, opts: dict[str, Any]) -> list[str]:
        """Checks a local volume's driver_opts; returns the problems with mounts from the host or the network.

        A device must be an absolute path inside the mount roots.
        """
        # The local driver can turn a named volume into a bind mount or a network mount.
        problems = unknown_keys(opts, VOLUME_DRIVER_OPTS, "driver_opts key", extensions=False)
        kind = opts.get("type", "")
        if kind not in LOCAL_VOLUME_TYPES:
            return [*problems, f"driver_opts type {kind!r} is not allowed"]
        device = opts.get("device", "")
        if kind == "tmpfs":
            # The kernel ignores the filesystem type when the bind flag is set, so tmpfs with `bind`
            # mounts whatever `device` names.
            if device not in ("", "tmpfs") or mount_flags(opts) & BIND_FLAGS:
                problems.append("a tmpfs volume must not name a device or bind")
            return problems
        if not device:
            return [*problems, *(["bind needs a device"] if mount_flags(opts) & BIND_FLAGS else [])]
        if not os.path.isabs(device):  # the daemon would resolve it against its own working directory
            return [*problems, f"device {device!r} must be an absolute path"]
        if not is_inside_any(device, self.mount_roots):
            return [*problems, self._outside(f"device {device!r}")]
        return problems

    def _check_network(self, key: str, network: dict[str, Any] | None, project: str | None) -> list[str]:
        """Checks the top-level network called key; returns problems with its keys, scope, drivers and
        options.
        """
        network = network or {}
        problems = [*unknown_keys(network, NETWORK_KEYS, "key"), *_check_scope(key, network, project)]
        if network.get("driver") not in NETWORK_DRIVERS:
            problems.append(f"driver {network.get('driver')!r} is not allowed")
        problems += unknown_keys(network.get("driver_opts") or {}, NETWORK_DRIVER_OPTS, "driver_opts key")
        ipam = network.get("ipam") or {}
        problems += unknown_keys(ipam, IPAM_KEYS, "ipam key")
        if ipam.get("driver") not in (None, "", "default"):
            problems.append(f"ipam driver {ipam['driver']!r} is not allowed")
        return problems

    def _check_file_sources(self, config: dict[str, Any]) -> list[Finding]:
        """Checks the top-level secrets and configs, whose files building and running read from the host."""
        problems = []
        for kind in ("secrets", "configs"):
            for key, item in (config.get(kind) or {}).items():
                problems += refused(self._check_file_source(item), f"{kind} {key}")
        return problems

    def _check_file_source(self, item: dict[str, Any] | None) -> list[str]:
        """Checks one secret or config; returns its unknown keys, and a problem if it is external, copies a
        variable, or names a file outside the project.
        """
        item = item or {}
        problems = unknown_keys(item, SECRET_KEYS, "key")
        if item.get("external"):
            problems.append("external resources are not allowed, they may belong to another project")
        if item.get("environment"):
            problems.append(
                f"environment {item['environment']!r} copies a variable from dockscreen's environment")
        source = item.get("file")
        if source and not is_inside(source, self.project_dir):
            problems.append(f"file {source!r} is outside {self.project_dir}")
        return problems

    def _outside(self, subject: str) -> str:
        """Returns the problem that subject is outside the mount roots, with how the config file can allow
        it.
        """
        text = f"{subject} is outside {_roots_text(self.mount_roots)}"
        if self.config_file:
            text += (f"; to allow it, add a directory that contains it to mount_dirs under "
                     f"[projects.\"{self.project_dir}\"] in {self.config_file}")
        return text

    # --- what else the project and the command line choose ------------------------

    def check_daemon(self, remote: bool) -> list[Finding]:
        """Checks the daemon a command talks to; returns a refusal if it may not be this host's own
        (remote), since the checks compare ids and paths with this host's.
        """
        return [Finding(REMOTE_MESSAGE)] if remote else []

    def check_location(self, location: Location) -> list[Finding]:
        """Checks where a project is; returns a refusal for each reason its directory cannot be the one its
        bind mounts are judged against.
        """
        found = []
        if location.foreign:
            found.append(Finding(f"the nearest compose file is in {location.directory}, which is your home "
                                 "directory or not yours; run from the project directory or use -f"))
        found += [Finding(f"{path} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR; set it in your shell or use "
                          "-f, so the project directory can be verified") for path in location.redirects]
        if location.sensitive:
            found.append(Finding(f"the project directory {location.directory} contains "
                                 f"{location.sensitive[0]}; move the compose file into a directory of its "
                                 "own"))
        return found

    def check_project_name(self, name: str, directory: str, made_from: Iterable[str]) -> list[Finding]:
        """Checks that the project in directory may use its name; returns a refusal if containers with that
        project name were made from another directory.

        The name is the project's own choice (`name:`, or `COMPOSE_PROJECT_NAME` in its `.env`), and it
        decides which volumes, networks and containers compose uses, replaces and, for `down -v`, removes.
        made_from: the directories the containers with that project name say they were made from, "" for
        a container that does not say, which cannot be shown to come from directory.
        """
        here = os.path.realpath(directory)
        others = sorted({path for path in made_from if not path or os.path.realpath(path) != here})
        if not others:
            return []
        shown = ", ".join(repr(path) if path else "an unknown directory" for path in others)
        return [Finding(f"project name {name!r} is used by containers made from {shown}, not from {here}",
                        help="pass -p NAME to choose the name yourself")]

    def check_user_options(self, options: Iterable[UserOption]) -> list[Finding]:
        """Checks the users a command line gives (check_user_option, check_as_option); returns the
        refusals.
        """
        found = []
        for option in options:
            if option.flag == "--as":
                found += self.check_as_option(option.value, option.account)
            else:
                found += self.check_user_option(option.value)
        return found

    def check_user_option(self, spec: str) -> list[Finding]:
        """Checks a user that --user or -u gives; returns a refusal unless it is numeric `uid:gid`.

        A name would be resolved in the image, or for exec in the running container, which the image
        controls. A uid alone would leave the group to the image: docker takes it, and the supplementary
        groups, from the image's own passwd and group files, which can say root.
        """
        if ids.parse_user(spec):
            return []
        hint = "; give the group too, as uid:gid" if ids.is_id(spec) else ""
        return [Finding(f"--user takes numeric ids as uid:gid, not {spec!r}{hint}{USER_OPTION_ALTERNATIVES}")]

    def check_as_option(self, name: str, account: tuple[int, int] | None) -> list[Finding]:
        """Checks the name that --as gives and the account of that name on this host (None: there is none);
        returns a refusal unless it names an account here.
        """
        if not name or ":" in name or ids.is_id(name):
            return [Finding(f"--as takes the name of a local user, not {name!r}; use --user for ids")]
        if account is None:
            return [Finding(f"user {name!r} does not exist on this host; use --user with a numeric id")]
        return []


def _check_outputs(outputs: Sequence[Any], cache_to: Sequence[Any]) -> list[str]:
    """Returns the problems with a bake target's output and cache-to entries: any that write to the host."""
    problems = []
    for entry in outputs:
        found = fields(entry)
        # a bare path is a local directory
        if found is None or found.get("type") not in BAKE_OUTPUT_TYPES or "dest" in found:
            problems.append(f"output {entry!r} writes to the host and is not allowed")
    for entry in cache_to:
        found = fields(entry)
        if found is None or found.get("type") not in BAKE_CACHE_TO_TYPES:
            problems.append(f"cache-to {entry!r} writes to the host or an unknown store and is not allowed")
    return problems


# A check of one service key: takes the Policy, the value and the service, returns the problems.
Check = Callable[[Policy, Any, Subject], list[str]]


def _forbidden(key: str) -> Check:
    """Returns a check that refuses key whenever it carries a value."""
    return lambda policy, value, service: [f"{key} is not allowed"] if value else []


def _check_namespace(key: str) -> Check:
    """Returns a check for the namespace key that refuses the host's namespace and other containers'."""
    def check(policy: Policy, value: Any, service: Subject) -> list[str]:
        text = str(value)
        if text == "host" or text.startswith("container:"):
            return [f"{key}: {text} shares a namespace outside the project"]
        return []
    return check


def _check_host_files(key: str) -> Check:
    """Returns a check for key (env_file or label_file) that refuses files outside the project directory.

    These keys only show up in the definition when it is loaded without env resolution.
    """
    def check(policy: Policy, value: Any, service: Subject) -> list[str]:
        problems = []
        for entry in [value] if isinstance(value, (str, dict)) else value or []:
            path = entry.get("path") if isinstance(entry, dict) else entry
            if path and not is_inside(path, policy.project_dir):
                problems.append(f"{key} {path!r} is outside {policy.project_dir}")
        return problems
    return check


def _check_hooks(key: str) -> Check:
    """Returns a check for the hook key (post_start or pre_stop) that refuses hooks that escalate.

    Those are hooks with unknown keys, privileged ones, and ones whose user Policy.check_user refuses.
    """
    def check(policy: Policy, value: Any, service: Subject) -> list[str]:
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
    "user": Policy.check_user,
    "cap_drop": Policy.check_cap_drop,
    "security_opt": Policy.check_security_opt,
    **{key: _forbidden(key) for key in FORBIDDEN_KEYS},
    "runtime": Policy._check_runtime,
    **{key: _check_namespace(key) for key in NAMESPACE_KEYS},
    "volumes": Policy._check_mounts,
    "volumes_from": Policy._check_volumes_from,
    "build": Policy._check_build,
    "env_file": _check_host_files("env_file"),
    "label_file": _check_host_files("label_file"),
    "develop": Policy._check_develop,
    "deploy": Policy._check_deploy,
    "post_start": _check_hooks("post_start"),
    "pre_stop": _check_hooks("pre_stop"),
}


# --- helpers ----------------------------------------------------------------

def unknown_keys(mapping: Mapping[str, Any], allowed: Collection[str], what: str,
                 extensions: bool = True) -> list[str]:
    """Returns a problem for each key of mapping not in allowed; `x-` keys pass unless extensions is False.

    what: names the kind of key in the problems.
    """
    return [
        f"{what} {key!r} is not on the allow list"
        for key in mapping
        if key not in allowed and not (extensions and str(key).startswith("x-"))
    ]


def _check_service_names(config: dict[str, Any]) -> list[str]:
    """Returns a problem for each service name that starts with `-`, which compose would read as an option."""
    return [f"service name {name!r} starts with '-', which compose would read as an option"
            for name in config.get("services") or {} if str(name).startswith("-")]


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


def _is_host_path(source: Any) -> bool:
    """Tells whether a build source is a path on this host, not a URL (`git://`, ...) or a service."""
    text = str(source)
    return "://" not in text and not text.startswith("service:")


def _check_scope(key: str, item: dict[str, Any], project: str | None) -> list[str]:
    """Returns a problem unless the volume or network item called key belongs to project, by its name.

    External ones are refused. Without a project name there is nothing to compare; Policy.check_project
    refuses that.
    """
    if item.get("external"):
        return ["external resources are not allowed, they may belong to another project"]
    if not project:
        return []
    # compose's own name for it; a name set in the file can be that of another project's volume or network
    expected = f"{project}_{key}"
    if item.get("name") != expected:
        return [f"name {item.get('name')!r} is not the project-scoped {expected!r}"]
    return []


def _roots_text(mount_roots: Sequence[str]) -> str:
    """Names mount_roots for a message."""
    project_dir, *extra = mount_roots
    return f"{project_dir}" + (" and the configured mount_dirs" if extra else "")


def is_inside_any(path: str, roots: Iterable[str]) -> bool:
    """Tells whether path is inside one of roots (is_inside)."""
    return any(is_inside(path, root) for root in roots)


def is_inside(path: str, root: str) -> bool:
    """Tells whether path, resolved relative to root and through symlinks, is root or below it."""
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(real_root, path))
    return os.path.commonpath([real_root, real]) == real_root
