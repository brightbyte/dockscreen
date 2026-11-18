"""This module defines the ProjectRules class, the group of the policy's rules for judging the parts of a
compose project besides its services: its top-level volumes, networks, secrets and configs, its location,
the daemon it runs on, and its name. The rules also judge what the project gets from around it: the
configured mount dirs, and variables from the shell."""

import os
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from dockscreen.model.mounts import BIND_FLAGS, mount_flags
from dockscreen.model.project import ProjectLocation
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.rules.base import RuleBase, is_inside, is_inside_any, unknown_key_problems

TOP_LEVEL_KEYS = frozenset({"name", "services", "volumes", "networks", "secrets", "configs", "version"})
VOLUME_KEYS = frozenset({"name", "driver", "driver_opts", "external", "labels"})
NETWORK_KEYS = frozenset({
    "name", "driver", "driver_opts", "external", "internal", "attachable", "enable_ipv4", "enable_ipv6",
    "ipam", "labels",
})

IPAM_KEYS = frozenset({"driver", "config", "options"})
SECRET_KEYS = frozenset({"name", "file", "environment", "content", "external", "labels"})

# Volume driver_opts types that stay on this host's file system or in memory. The local driver passes
# type, device and o to mount(2), which the daemon runs as root. So `type: nfs` or `cifs` mounts a network
# share from this host's position in the network, with credentials in `o`, and `type: ext4,
# device: /dev/sda1` mounts a host disk. Only `none` and tmpfs are allowed; `none` is a bind mount, whose
# device _check_driver_opts checks.
LOCAL_VOLUME_TYPES = frozenset({"", "none", "tmpfs"})
# The local driver passes every other key on too, and a local volume needs none of them.
VOLUME_DRIVER_OPTS = frozenset({"type", "device", "o"})
# The drivers bridge and none keep the container behind the host's NAT. The drivers macvlan and ipvlan put
# the container on the host's own network, with an address of its own, past the host's firewall. The
# drivers host and overlay give the host's network and a swarm's network. A plugin driver is code on the
# host.
NETWORK_DRIVERS = frozenset({None, "", "bridge", "none"})
# The bridge driver's other options can attach the network to an existing bridge (bridge.name), turn off
# masquerading, or publish ports without NAT. The MTU changes nothing but packet sizes.
NETWORK_DRIVER_OPTS = frozenset({"com.docker.network.driver.mtu"})
REMOTE_MESSAGE = "the daemon is not the default local one; ids and paths cannot be checked"


class ProjectRules(RuleBase):
    """Mixin of Policy with the rules for a compose project's resources, location, daemon and name, and for
    what the project gets from around it. It is not used on its own.
    """

    def _check_service_names(self, config: dict[str, Any]) -> list[str]:
        """Returns a problem for each service name that starts with `-`, which compose would read as an
        option.

        Service names go to compose as arguments (`docker compose pull web db`). A service called `--ssh`
        makes `compose build --ssh default`, which forwards the user's SSH agent into the build, and other
        options can change a command's effect. dockscreen puts `--` before the names that it passes itself.
        Refusing the names also keeps them out of compose's own commands.
        """
        return [f"service name {name!r} starts with '-', which compose would read as an option"
                for name in config.get("services") or {} if str(name).startswith("-")]

    def _check_volume(self, key: str, volume: dict[str, Any] | None, project: str | None,
                      directory: str) -> list[str]:
        """Checks the top-level volume called key, of the project called project, whose directory is
        directory. Returns the problems with its keys, scope, driver and driver_opts.
        """
        volume = volume or {}
        problems = [*unknown_key_problems(volume, VOLUME_KEYS, "key"), *_check_scope(key, volume, project)]
        # A volume plugin is code on the host that mounts anything its code chooses: sshfs, a host path.
        driver = volume.get("driver")
        if driver not in (None, "", "local"):
            return [*problems, f"driver {driver!r} is not allowed"]
        return [*problems, *self._check_driver_opts(volume.get("driver_opts") or {}, directory)]

    def _check_driver_opts(self, driver_opts: dict[str, Any], directory: str) -> list[str]:
        """Checks a local volume's driver_opts, for a project in directory. Returns the problems with mounts
        from the host or the network.

        A device must be an absolute path inside the mount roots.

        The local driver can turn a named volume into a bind mount (`type: none, o: bind, device: /`) or a
        network mount. The `volumes:` of a service only names the volume, so the service's own check sees a
        volume, not a host path. This check therefore holds the device of a bind to the same roots as a bind
        mount's source. A service that uses such a volume also counts as reaching host files for the id
        rules (mounts.service_reaches_host).
        """
        problems = unknown_key_problems(driver_opts, VOLUME_DRIVER_OPTS, "driver_opts key",
                                        allows_extensions=False)
        kind = driver_opts.get("type", "")
        if kind not in LOCAL_VOLUME_TYPES:
            return [*problems, f"driver_opts type {kind!r} is not allowed"]
        device = driver_opts.get("device", "")
        if kind == "tmpfs":
            # The kernel ignores the filesystem type when the bind flag is set, so tmpfs with `bind`
            # mounts whatever `device` names.
            if device not in ("", "tmpfs") or mount_flags(driver_opts) & BIND_FLAGS:
                problems.append("a tmpfs volume must not name a device or bind")
            return problems
        if not device:
            return [*problems, *(["bind needs a device"] if mount_flags(driver_opts) & BIND_FLAGS else [])]
        if not os.path.isabs(device):  # the daemon would resolve it against its own working directory
            return [*problems, f"device {device!r} must be an absolute path"]
        if not is_inside_any(device, self.mount_roots(directory)):
            return [*problems, self._outside_problem(f"device {device!r}", directory)]
        return problems

    def _check_network(self, key: str, network: dict[str, Any] | None, project: str | None) -> list[str]:
        """Checks the top-level network called key. Returns the problems with its keys, scope, drivers and
        options (see NETWORK_DRIVERS and NETWORK_DRIVER_OPTS). A plugin IPAM driver is code on the host too.
        """
        network = network or {}
        problems = [*unknown_key_problems(network, NETWORK_KEYS, "key"), *_check_scope(key, network, project)]
        if network.get("driver") not in NETWORK_DRIVERS:
            problems.append(f"driver {network.get('driver')!r} is not allowed")
        problems += unknown_key_problems(network.get("driver_opts") or {}, NETWORK_DRIVER_OPTS,
                                         "driver_opts key")
        ipam = network.get("ipam") or {}
        problems += unknown_key_problems(ipam, IPAM_KEYS, "ipam key")
        if ipam.get("driver") not in (None, "", "default"):
            problems.append(f"ipam driver {ipam['driver']!r} is not allowed")
        return problems

    def _check_file_sources(self, config: dict[str, Any], directory: str) -> list[Finding]:
        """Checks the top-level secrets and configs of the project in directory. Building and running the
        project read their files from the host.
        """
        problems = []
        for kind in ("secrets", "configs"):
            for key, item in (config.get(kind) or {}).items():
                problems += finding.refusals(self._check_file_source(item, directory), f"{kind} {key}")
        return problems

    def _check_file_source(self, item: dict[str, Any] | None, directory: str) -> list[str]:
        """Checks one secret or config. Returns its unknown keys, and a problem if it is external, if it
        copies a variable, or if it names a file outside directory.

        Compose reads the file on the host and mounts it into the container. So a file outside the project
        hands the container host files (~/.ssh/id_ed25519). `environment:` copies a variable from the
        environment that compose runs in, which is the user's shell; the project picks which of the user's
        secrets to take (AWS_SECRET_ACCESS_KEY). An external secret or config is a secret or config that
        someone else created.
        """
        item = item or {}
        problems = unknown_key_problems(item, SECRET_KEYS, "key")
        if item.get("external"):
            problems.append("external resources are not allowed, they may belong to another project")
        if item.get("environment"):
            problems.append(
                f"environment {item['environment']!r} copies a variable from dockscreen's environment")
        source = item.get("file")
        if source and not is_inside(source, directory):
            problems.append(f"file {source!r} is outside {directory}")
        return problems

    def check_daemon(self, is_remote: bool) -> list[Finding]:
        """Checks the daemon that a command talks to. Returns a refusal if the daemon may not be this host's
        own (is_remote), because the checks compare ids and paths with this host's.
        """
        return [Finding(REMOTE_MESSAGE)] if is_remote else []

    def check_location(self, location: ProjectLocation) -> list[Finding]:
        """Checks the location of a project. Returns a refusal for each reason that its directory cannot be
        the one that the policy judges its bind mounts against.

        A project may mount everything inside its directory, so the directory must be one that the project
        owns:
        - foreign: compose searches upwards for a compose file. A compose file placed in the user's home
          directory, or in a directory of another user's, makes that directory the project directory, and puts
          ~/.ssh
          "inside" it;
        - redirects: a `.env` that sets COMPOSE_FILE (or its separator) makes compose read files elsewhere.
          Then compose uses a directory other than the one that dockscreen located and the policy checked;
        - sensitive: a project directory that contains a sensitive path (/, $HOME, the config files, the
          docker socket) puts it inside the project.
        """
        findings = []
        if location.is_foreign:
            findings.append(Finding(f"the nearest compose file is in {location.directory}, which is your "
                                    "home directory or not yours; run from the project directory or use -f"))
        findings += [Finding(f"{path} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR; set it in your shell or "
                             "use -f, so the project directory can be verified")
                     for path in location.redirects]
        if location.sensitive_paths:
            findings.append(Finding(f"the project directory {location.directory} contains "
                                    f"{location.sensitive_paths[0]}; move the compose file into a directory "
                                    "of its own"))
        return findings

    def check_mount_dirs(self, sensitive_paths: Mapping[str, Sequence[str]]) -> list[Notice]:
        """Checks the configured mount dirs for the sensitive paths that they contain. Returns a warning for
        each mount dir that contains such a path, because containers can mount that path.

        Parameters:
        - sensitive_paths: by mount dir, the sensitive paths it equals or contains
        """
        return [Notice(f"the configured mount dir {directory} contains {paths[0]}, so containers can "
                       "mount it", NoticeSeverity.WARNING, help="narrow mount_dirs in the config file")
                for directory, paths in sensitive_paths.items() if paths]

    def check_shell_env(self, copied_variables: Mapping[str, Sequence[str]]) -> list[Notice]:
        """Checks the variables that the project's services take from the shell. Returns a warning for each
        service that takes any, without the values of the variables.

        `environment: [AWS_SECRET_ACCESS_KEY]`, a name without a value, makes compose copy the user's
        variable into the container. The user's shell is trusted, so the policy does not refuse this. But
        the project chooses the variables, and the user should know which ones leave.

        Parameters:
        - copied_variables: by service, the names of the variables it takes from the shell
        """
        return [Notice(f"environment variables taken from your shell: {', '.join(names)}",
                       NoticeSeverity.WARNING, f"service {name}",
                       "unset them in your shell, or give the project literal values, to keep them out")
                for name, names in copied_variables.items() if names]

    def check_project_name(self, name: str, directory: str,
                           working_directories: Iterable[str]) -> list[Finding]:
        """Checks that the project, whose directory is directory, may use its name. Returns a refusal if
        containers with that project name were made from another directory.

        The name is the project's own choice (`name:`, or `COMPOSE_PROJECT_NAME` in its `.env`). It decides
        which volumes, networks and containers compose uses and replaces, and, for `down -v`, removes.

        Parameters:
        - name: the project name
        - directory: the project directory
        - working_directories: the directories that the containers with that project name were made from,
          by their labels; "" for a container without a label, which cannot be shown to come from directory
        """
        real_directory = os.path.realpath(directory)
        other_directories = sorted({path for path in working_directories
                                    if not path or os.path.realpath(path) != real_directory})
        if not other_directories:
            return []
        shown_paths = ", ".join(repr(path) if path else "an unknown directory" for path in other_directories)
        return [Finding(f"project name {name!r} is used by containers made from {shown_paths}, not from "
                        f"{real_directory}",
                        help="pass -p NAME to choose the name yourself")]


def _check_scope(key: str, item: dict[str, Any], project: str | None) -> list[str]:
    """Returns a problem unless the volume or network item called key belongs to project, by its name.

    Compose names a volume `<project>_<key>`. But `name:` replaces that name, and `external: true` uses a
    volume that exists already. Either way, the project gets a volume that another project or the user
    created: with its data, or with driver_opts that bind a host path, which this check never saw. The same
    goes for networks, which would put the container next to another project's services. This refuses
    external volumes and networks. Without a project name there is nothing to compare; Policy.check_project
    refuses a project without a name.
    """
    if item.get("external"):
        return ["external resources are not allowed, they may belong to another project"]
    if not project:
        return []
    # compose's own name for it; a name that the file sets can be the name of another project's volume or
    # network
    expected_name = f"{project}_{key}"
    if item.get("name") != expected_name:
        return [f"name {item.get('name')!r} is not the project-scoped {expected_name!r}"]
    return []
