"""This module defines the ProjectRules class, the group of the policy's rules for judging what a compose
project has besides its services: its top-level volumes, networks, secrets and configs, where it is, the
daemon it runs on, and its name; and what it gets from around it: the configured mount dirs, and variables
from the shell."""

import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from dockscreen.model.mounts import BIND_FLAGS, mount_flags
from dockscreen.model.project import ProjectLocation
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.rules.base import RuleBase, is_inside, is_inside_any, unknown_keys

TOP_LEVEL_KEYS = frozenset({"name", "services", "volumes", "networks", "secrets", "configs", "version"})
VOLUME_KEYS = frozenset({"name", "driver", "driver_opts", "external", "labels"})
NETWORK_KEYS = frozenset({
    "name", "driver", "driver_opts", "external", "internal", "attachable", "enable_ipv4", "enable_ipv6",
    "ipam", "labels",
})

IPAM_KEYS = frozenset({"driver", "config", "options"})
SECRET_KEYS = frozenset({"name", "file", "environment", "content", "external", "labels"})

# Volume driver_opts types that stay on this host's filesystem or memory.
LOCAL_VOLUME_TYPES = frozenset({"", "none", "tmpfs"})
VOLUME_DRIVER_OPTS = frozenset({"type", "device", "o"})
NETWORK_DRIVERS = frozenset({None, "", "bridge", "none"})
NETWORK_DRIVER_OPTS = frozenset({"com.docker.network.driver.mtu"})
REMOTE_MESSAGE = "the daemon is not the default local one; ids and paths cannot be checked"


class ProjectRules(RuleBase):
    """Mixin of Policy with the rules for a compose project's resources, location, daemon and name, and what
    it gets from around it, not used on its own.
    """

    def _check_service_names(self, config: dict[str, Any]) -> list[str]:
        """Returns a problem for each service name that starts with `-`, which compose would read as an
        option.
        """
        return [f"service name {name!r} starts with '-', which compose would read as an option"
                for name in config.get("services") or {} if str(name).startswith("-")]

    def _check_volume(self, key: str, volume: dict[str, Any] | None, project: str | None,
                      directory: str) -> list[str]:
        """Checks the top-level volume called key of the project called project in directory; returns
        problems with its keys, scope, driver, driver_opts.
        """
        volume = volume or {}
        problems = [*unknown_keys(volume, VOLUME_KEYS, "key"), *_check_scope(key, volume, project)]
        driver = volume.get("driver")
        if driver not in (None, "", "local"):
            return [*problems, f"driver {driver!r} is not allowed"]
        return [*problems, *self._check_driver_opts(volume.get("driver_opts") or {}, directory)]

    def _check_driver_opts(self, opts: dict[str, Any], directory: str) -> list[str]:
        """Checks a local volume's driver_opts for a project in directory; returns the problems with mounts
        from the host or the network.

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
        if not is_inside_any(device, self.mount_roots(directory)):
            return [*problems, self._outside(f"device {device!r}", directory)]
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

    def _check_file_sources(self, config: dict[str, Any], directory: str) -> list[Finding]:
        """Checks the top-level secrets and configs of the project in directory, whose files building and
        running read from the host.
        """
        problems = []
        for kind in ("secrets", "configs"):
            for key, item in (config.get(kind) or {}).items():
                problems += finding.refusals(self._check_file_source(item, directory), f"{kind} {key}")
        return problems

    def _check_file_source(self, item: dict[str, Any] | None, directory: str) -> list[str]:
        """Checks one secret or config; returns its unknown keys, and a problem if it is external, copies a
        variable, or names a file outside directory.
        """
        item = item or {}
        problems = unknown_keys(item, SECRET_KEYS, "key")
        if item.get("external"):
            problems.append("external resources are not allowed, they may belong to another project")
        if item.get("environment"):
            problems.append(
                f"environment {item['environment']!r} copies a variable from dockscreen's environment")
        source = item.get("file")
        if source and not is_inside(source, directory):
            problems.append(f"file {source!r} is outside {directory}")
        return problems

    def check_daemon(self, remote: bool) -> list[Finding]:
        """Checks the daemon a command talks to; returns a refusal if it may not be this host's own
        (remote), since the checks compare ids and paths with this host's.
        """
        return [Finding(REMOTE_MESSAGE)] if remote else []

    def check_location(self, location: ProjectLocation) -> list[Finding]:
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

    def check_mount_dirs(self, sensitive: Mapping[str, Sequence[str]]) -> list[Notice]:
        """Checks the configured mount dirs, by the sensitive paths that each contains; returns a warning
        for each that contains one, since its containers can mount it.

        Parameters:
        - sensitive: by mount dir, the sensitive paths it equals or contains
        """
        return [Notice(f"the configured mount dir {directory} contains {paths[0]}, so containers can "
                       "mount it", NoticeSeverity.WARNING, help="narrow mount_dirs in the config file")
                for directory, paths in sensitive.items() if paths]

    def check_shell_env(self, copied: Mapping[str, Sequence[str]]) -> list[Notice]:
        """Checks what the project's services take from the shell; returns a warning for each service
        that takes any, without their values.

        Parameters:
        - copied: by service, the names of the variables it takes from the shell
        """
        return [Notice(f"environment variables taken from your shell: {', '.join(names)}",
                       NoticeSeverity.WARNING, f"service {name}",
                       "unset them in your shell, or give the project literal values, to keep them out")
                for name, names in copied.items() if names]

    def check_project_name(self, name: str, directory: str, made_from: Iterable[str]) -> list[Finding]:
        """Checks that the project in directory may use its name; returns a refusal if containers with that
        project name were made from another directory.

        The name is the project's own choice (`name:`, or `COMPOSE_PROJECT_NAME` in its `.env`), and it
        decides which volumes, networks and containers compose uses, replaces and, for `down -v`, removes.

        Parameters:
        - name: the project name
        - directory: the project directory
        - made_from: the directories the containers with that project name say they were made from, "" for a
          container that does not say, which cannot be shown to come from directory
        """
        here = os.path.realpath(directory)
        others = sorted({path for path in made_from if not path or os.path.realpath(path) != here})
        if not others:
            return []
        shown = ", ".join(repr(path) if path else "an unknown directory" for path in others)
        return [Finding(f"project name {name!r} is used by containers made from {shown}, not from {here}",
                        help="pass -p NAME to choose the name yourself")]


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
