# dockscreen scenarios

Audience: people who change dockscreen or review its security. Each scenario is a way a hostile compose project or image could try to get past the policy in [design.md](design.md), with the attack, dockscreen's defense and its place in the code, and the tests that show it.

The test references take the form `file::test`; "unit" tests simulate docker, "e2e" tests run against the real docker of the host ([tests/e2e/README.md](../tests/e2e/README.md)). A scenario says so when its defense depends on a daemon's behaviour that no test runs. The code documents each defense where it is made; the pointers below lead there.

The sections group the scenarios by the attacker's goal: host files, privileges, a user it should not have, a difference between the checked thing and the running one, a build that reaches the host, another project's resources, or dockscreen itself.

## Host files

Goal: a container, or compose on the container's behalf, that reads or writes host paths outside the project: `~/.ssh`, `/etc`, the docker socket (which is root on the host).

### H1. A bind mount from outside the project

`volumes: ["/:/host"]`, or the same through a path that only looks inside: a symlink in the project (`data -> /etc`), `..`, `~` (compose expands it), `/proc/1/root` (the host root through procfs), `/var/run/docker.sock`.

- Defense: a bind source must be inside the project or a configured `mount_dirs` entry, compared after resolving symlinks, since docker follows them (`ServiceRules._check_mounts`, `base.is_inside`). The rule is "outside the project", not a list of dangerous paths.
- Tests: unit `test_policy.py::test_bind_mount_outside_project_is_refused`, `::test_bind_mount_through_symlink_out_of_project_is_refused`; e2e `test_e2e_compose_mounts.py::test_a_bind_mount_from_outside_the_project_is_refused` (including the socket and `/proc/1/root`), `::test_a_symlink_in_the_project_is_followed_out_of_it`.
- Known gap: the check sees the file system as it is when it runs. A container that can write the project could replace a directory with a link before docker creates the next container; dockscreen does not pin the directories.

### H2. A named volume that is a host mount

```yaml
volumes:
  d: {driver_opts: {type: none, o: bind, device: /}}
  t: {driver_opts: {type: tmpfs, device: /etc, o: bind}}
```

The service's `volumes:` only names `d`, so its own check sees no host path. The local driver passes `type`, `device` and `o` to mount(2), and the kernel ignores the filesystem type when the bind flag is set: `t` is the host's `/etc`, not memory. `type: nfs` or `cifs` mounts a network share from this host's position; a volume plugin can mount anything.

- Defense: the policy allows only the local driver and the types `none` and `tmpfs`; it holds a bind's device to the same roots as a bind mount; a tmpfs may name no device and no bind flag, however `o` spells it; the policy refuses other `driver_opts` keys (`ProjectRules._check_driver_opts`, `LOCAL_VOLUME_TYPES`). A service that uses such a volume counts as reaching host files for the id rules (`mounts.service_reaches_host`, see U5).
- Tests: unit `test_policy.py::test_volume_drivers_and_options`, `::test_a_tmpfs_volume_cannot_be_made_a_bind_mount_of_a_host_path`, `::test_volume_driver_opts_are_an_allowlist_and_bind_needs_a_device`; e2e `test_e2e_compose_mounts.py::test_a_named_volume_that_is_not_the_projects_own_is_refused`.

### H3. Files that compose reads on the host

Content from outside the project reaches a container without a mount:

| Key | Example | Defense |
|---|---|---|
| `env_file`, `label_file` | `~/.aws/credentials` | inside the project (`servicerules._check_host_files`); dockscreen loads the config with `--no-env-resolution` so the path stays visible |
| `secrets`, `configs` | `file: ~/.ssh/id_ed25519`, `environment: AWS_SECRET_ACCESS_KEY` | file inside the project, no variables, not external (`ProjectRules._check_file_source`) |
| `develop.watch` | `path: ~/.aws`, `action: sync` | inside the project (`ServiceRules._check_develop`) |
| `volumes_from` | `container:other` | only services of the project (`ServiceRules._check_volumes_from`) |
| `environment` | `[AWS_SECRET_ACCESS_KEY]` | the user's shell is trusted, so the policy does not refuse it; a warning names the variables (`ProjectRules.check_shell_env`) |

- Tests: unit `test_policy.py::test_secrets_and_configs`, `::test_env_and_label_files_outside_project_are_refused`, `::test_develop_watch`, `::test_privilege_escalation_is_refused` (`volumes_from`); e2e `test_e2e_compose_mounts.py::test_a_secret_or_config_from_outside_the_project_is_refused`, `::test_a_file_read_on_the_host_from_outside_the_project_is_refused`, `::test_a_watch_path_outside_the_project_is_refused`, `::test_volumes_of_another_container_are_refused`.
- Untested: `include` and `extends` of files outside the project or from git or OCI sources. Compose merges them into the config that the policy checks, so it judges their additions like the rest, but no test shows it. A volume `subpath` with `..` relies on the daemon's own check.

### H4. A project directory that is not the project's

A project may mount everything inside its directory, so it tries to make a bigger directory its own: a compose file in `~` or in a parent directory found by compose's upward search, a `.env` that sets `COMPOSE_FILE` to send compose elsewhere, or a project directory that contains `/etc` or the config files.

- Defense: dockscreen stops the search at `$HOME` and at directories the user does not own; the policy refuses `COMPOSE_FILE` and `COMPOSE_PATH_SEPARATOR` in `.env`, and a project directory that contains a sensitive path (`ProjectRules.check_location`, `inspect.SENSITIVE_DIRS`).
- Tests: unit `test_inspect.py::test_compose_vars_in_dotenv_make_the_project_directory_unverifiable`, `::test_a_project_directory_containing_the_home_directory_is_refused`, `::test_the_walk_up_stops_at_the_home_directory`; e2e `test_e2e_compose_project.py::test_a_dotenv_that_points_compose_elsewhere_is_refused`, `::test_a_project_directory_that_contains_the_root_is_refused`. The stop at `$HOME` has no e2e test; it depends on the host's layout.

## Privileges

Goal: root on the host through the kernel or the daemon, from a container that runs as an unprivileged user.

### P1. Privileges, devices and other runtimes

`privileged`, `cap_add` (`SYS_ADMIN`, `DAC_READ_SEARCH`), `devices` (`/dev/sda`), `device_cgroup_rules`, `gpus` and device reservations, `cgroup_parent`, `runtime` other than runc, `external_links`.

- Defense: refused whenever set (`servicerules.FORBIDDEN_KEYS`, `_check_runtime`, `_check_deploy`); each key's comment names the access it opens.
- Tests: unit `test_policy.py::test_privilege_escalation_is_refused`; e2e `test_e2e_compose_services.py::test_a_service_that_asks_for_privileges_is_refused`.

### P2. The host's namespaces

`pid: host` (the host's processes, and their files through `/proc/PID/root`), `network_mode: host` (services that listen on the host's 127.0.0.1, such as a docker API on tcp), `ipc`, `uts`, `userns_mode: host` (turns off user namespace remapping), `cgroup`, and `container:NAME` for each.

- Defense: neither `host` nor `container:` (`servicerules.NAMESPACE_KEYS`).
- Tests: unit `test_policy.py::test_privilege_escalation_is_refused` (pid, network_mode, ipc only); e2e `test_e2e_compose_services.py::test_a_service_that_shares_a_namespace_of_the_host_is_refused` (all six), `::test_a_service_that_joins_another_containers_namespace_is_refused`.

### P3. A setuid binary in the image

The image runs as an unprivileged user, as checked, and ships a setuid-root binary (`sudo`, or one made for the purpose).

- Defense: every service and `docker run` container gets `no-new-privileges` and `cap_drop: [ALL]` (`hardening`); the kernel then ignores the setuid bit, and a root process has no capabilities to override file permissions on mounts. A project cannot turn them off: `security_opt` allows only no-new-privileges and configured options, `cap_drop` must include `ALL` (`ServiceRules.check_security_opt`, `check_cap_drop`).
- Tests: unit `test_policy.py::test_cap_drop_all_is_required`, `::test_no_new_privileges_is_required`; e2e `test_e2e_compose_services.py::test_a_security_option_that_weakens_the_container_is_refused` (`seccomp=unconfined`, `apparmor=unconfined`), `::test_a_cap_drop_of_the_projects_own_is_extended_with_a_notice`.

### P4. Commands beside the main process

A `post_start` or `pre_stop` hook, or a `develop.watch` rule with `sync+exec`, runs a command in the container with a user and a `privileged` flag of its own.

- Defense: hooks may not be privileged, and their user passes the same rules as `user:`; the policy refuses `sync+exec` (`servicerules._check_hooks`, `WATCH_ACTIONS`).
- Tests: unit `test_policy.py::test_lifecycle_hooks_cannot_escalate`; e2e `test_e2e_compose_users.py::test_a_hook_may_not_run_as_root`, `test_e2e_compose_services.py::test_a_watch_rule_that_runs_a_command_in_the_container_is_refused`.

### P5. A key dockscreen does not know

A compose feature that Docker added after these rules (`models`, a new mount option) may be a new way out.

- Defense: an allowlist. Every structure has its own list of keys; the policy refuses an unknown key (`servicerules.HARMLESS_SERVICE_KEYS`, `base.unknown_keys`), except `x-` keys, which compose ignores, and not in `build`, where bake reads `x-bake`.
- Tests: unit `test_policy.py::test_unknown_service_key_is_refused_and_extension_keys_are_not`, `::test_unknown_keys_are_refused_in_nested_structures`; e2e `test_e2e_compose_services.py::test_keys_off_the_allow_list_are_refused_and_extension_fields_ignored`, `::test_a_service_that_uses_a_model_is_refused`.

## Users and ids

Goal: a container that runs as root, as an account of this host, or as the invoking user, which owns files on the host, although nobody chose that. The rules are in `rules.userrules`, whose docstring explains each id the rules refuse.

### U1. An image that runs as root

No `USER`, `USER 0`, a user whose group or a supplementary group is 0, or a passwd file written to be read as root by docker and as someone else by a careless parser (`app:x:1000x:...` is uid 0 to moby).

- Defense: the image's passwd and group files are read as moby reads them (`imageuser`), and an identity with 0 anywhere runs as the default user instead, pinned as numbers.
- Tests: unit `test_userrules.py::test_root_and_no_id_are_refused_in_every_position`, `test_imageuser.py::test_an_earlier_line_that_reads_as_root_wins_over_a_later_well_formed_one`, `test_serviceinfo.py::test_root_images_run_as_the_default_user_and_acceptable_ones_keep_their_own`; e2e `test_e2e_image_users.py::test_a_uid_that_is_not_a_number_counts_as_root`, `::test_a_member_of_the_root_group_counts_as_root`, `test_e2e_compose_images.py::test_an_image_that_would_run_as_root_runs_as_the_default_user`.

### U2. An id that is not root but owns something

`user: "1000:1000"` (an account of this host), an id in `/etc/subuid` (a rootless container's files), `65535` or `4294967295` (read as "no id"), or with host mounts any id outside the nobody range.

- Defense: the id rules (`UserRules.id_problem`).
- Tests: unit `test_userrules.py::test_ids_that_exist_on_this_host_are_refused_with_the_local_account_named`, `::test_subordinate_ranges_are_read_from_subuid_and_subgid`; e2e `test_e2e_compose_users.py::test_an_account_of_this_host_is_refused`, `::test_a_subordinate_id_is_refused`, `::test_a_user_the_project_may_not_choose_is_refused`.

### U3. An id that an older daemon wraps

`user: "4294967296:65534"`: an older daemon converts it to 32 bits, which gives uid 0, and `4294967296+1000` gives the invoking user's uid; an overflowing number is read as a name, which the image can define as 0. Current moby refuses both; this was not run against an older daemon.

- Defense: the policy refuses any id above 2147483647, with or without mounts (`userrules.MAX_ID`).
- Tests: unit `test_userrules.py::test_ids_above_the_largest_docker_accepts_are_refused_with_or_without_mounts`; e2e `test_e2e_compose_users.py::test_a_user_the_project_may_not_choose_is_refused`.

### U4. A name the image defines

`user: postgres`, where the image's passwd says `postgres:x:0:0`. Docker would resolve the name in the image; older daemons can look up a numeric group in `group_add` as a group name in the image first.

- Defense: dockscreen resolves names in a project on this host, never in the image, and the policy refuses those unknown here (`UserRules.resolve_user_names`); it refuses `group_add` for any value (`FORBIDDEN_KEYS`); `--user` on the command line takes numbers only (`userscreening`).
- Tests: unit `test_hardening.py::test_names_unknown_on_this_host_are_refused_even_if_the_image_defines_them`, `test_policy.py::test_group_add_is_refused_whatever_it_names`; e2e `test_e2e_compose_users.py::test_a_user_name_is_resolved_on_this_host_and_root_is_refused`, `test_e2e_compose_services.py::test_a_service_that_asks_for_privileges_is_refused` (`group_add`).

### U5. Mounts hidden from the id rules

A service with `user: "5000:5001"` and only a named volume that H2 would allow, bound to the project's files. The id decides the container's write access there, so the stricter rule for host mounts must apply.

- Defense: the policy works out whether a service reaches host files from the whole config, volumes included (`mounts.service_reaches_host`). `docker run` and `docker start` see a volume only by name and do not apply this.
- Tests: unit `test_mounts.py::test_a_named_volume_set_up_as_a_bind_mount_reaches_host_files`, `test_policy.py::test_the_id_rules_for_host_mounts_apply_to_a_service_of_a_bind_volume`; e2e `test_e2e_compose_mounts.py::test_a_named_volume_bound_to_the_project_is_a_host_mount_for_the_id_rules`.

### U6. Borrowing a trusted image's settings

The config file gives `mariadb` a user or mount dirs; the project builds or tags its own image as `mariadb` to get them.

- Defense: an image section applies only to an image with a repo digest for that repository, and never to a built one (`sections.section_for`, `serviceinfo._find_section_images`).
- Tests: unit `test_sections.py::test_an_image_that_only_has_the_name_does_not_get_the_section`, `test_projectscreening.py::test_an_image_section_that_its_image_does_not_prove_is_refused_before_anything_runs`; e2e `test_e2e_compose_images.py::test_an_image_section_does_not_apply_to_an_image_tagged_locally` is an expected failure: with the containerd image store, a local tag gets a repo digest. That is an open hole on such hosts ([security review, 1a](security-review.md)).

### U7. Running as the invoking user

`user: "${UID}:${GID}"`. A container that runs as the invoking user can write all of their files that it mounts, such as `.git/hooks` in the project, which they run later.

- Defense: the policy refuses the invoking user's ids unless they give `--allow-me` for the run; dockscreen sets `UID` and `GID` itself so that they are the real ids (`shellenv`).
- Tests: unit `test_policy.py::test_the_callers_own_ids_need_allow_me`, `test_userrules.py::test_the_callers_ids_are_refused_with_a_pointer_to_allow_me_and_allowed_with_it`; e2e `test_e2e_compose_users.py::test_the_callers_own_ids_need_allow_me`.

## Differences between check and run

Goal: pass the checks with one thing and run another.

### T1. A tag moved between check and run

Someone replaces the checked image `app:1` with a root image of the same name: by the project's `pull_policy: always`, a build, or anyone who can tag on this daemon.

- Defense: the generated file names each looked-at image by id, with `pull_policy: never` (`userrules._pinned`); dockscreen looks at images with `--pull=never`, by the id of the container it made from them (`imageusers._look`, `Screener.look`). `docker run` starts the very container it checked.
- Tests: unit `test_serviceinfo.py::test_a_looked_at_image_is_pinned_by_id_so_a_moved_tag_cannot_change_what_runs`; e2e `test_e2e_compose_images.py::test_an_image_that_would_run_as_root_runs_as_the_default_user` (asserts the pin). No e2e test moves a tag.

### T2. Compose reads the files differently

Interpolation, YAML anchors and merge keys, duplicate keys, a second `-f` on the command line, or a project file changed after the check.

- Defense: dockscreen never parses the project. The policy checks compose's own `config` output; dockscreen writes it to a private file, has compose read it back and compares the two before pulling anything, and gives compose that file as its only one, with the project directory and name pinned (`projectscreening`).
- Tests: unit `test_projectscreening.py::test_a_config_compose_would_read_differently_is_refused_and_not_run`, `::test_dollars_are_written_as_compose_printed_them`. No e2e test: nobody knows a way to make today's compose read its own output differently.

### T3. A service behind a profile

`profiles: [debug]` keeps a service out of the default config; `compose run debug` starts it anyway.

- Defense: dockscreen loads the config with `--profile '*'`, and a service named on the command line counts as started (`inspect._load_config`, `serviceinfo._services_to_run`).
- Tests: unit `test_serviceinfo.py::test_services_to_run_are_the_active_ones_plus_those_named`; e2e `test_e2e_compose_commands.py::test_run_checks_the_service_it_names_even_behind_a_profile`.

### T4. A `docker run` command line read differently

An option dockscreen does not know to take a value makes it take the value for the image, and judge another image or miss a `--user`.

- Defense: dockscreen compares the container docker created with its own reading (`containerscreening._verify_split`), and creates an accepted container again with `--user=uid:gid`.
- Tests: unit `test_docker_run.py::test_misread_command_line_is_refused_and_cleaned_up`; e2e `test_e2e_docker_run.py::test_an_option_dockscreen_does_not_know_fails_closed`.

### T5. A container created without dockscreen

Plain `docker create`, or a project's script, makes a container; `docker start` would run it unchecked.

- Defense: `start` and `restart` judge the existing container, which dockscreen cannot rewrite, and refuse one whose user dockscreen would have replaced (`containerscreening.check_existing`). Compose's own `start` and `restart` pass through: a known gap.
- Tests: unit `test_docker_start.py::test_existing_containers_cannot_be_rewritten_so_a_root_image_is_refused`; e2e `test_e2e_docker_start.py::test_a_container_that_would_run_as_root_is_refused`.

## Builds

Goal: a build that reads host files into an image, writes to the host, or uses the user's credentials.

### K1. `docker compose build`

`build: {context: /}`, a Dockerfile or `additional_contexts` outside, `ssh: [default]` (the user's SSH agent), `network: host`, `privileged: true`, `x-bake` (which `buildx bake` reads and can write outputs with).

- Defense: `BuildRules.check_build`, `_check_build`; build secrets name top-level secrets, checked as in H3.
- Tests: unit `test_policy.py::test_build_context_outside_project_is_refused`, `::test_unsafe_build_options_are_refused_when_building_and_running`; e2e `test_e2e_compose_commands.py::test_a_build_that_reaches_the_host_is_refused`, `::test_a_build_secret_from_outside_the_project_is_refused`.

### K2. `docker buildx bake`

The project's `docker-bake.hcl` sets `output = ["type=local,dest=/home/me/.ssh"]`, a local `cache-to`, `entitlements = ["security.insecure"]`, a secret from a variable, or keys bake adds later.

- Defense: bake's own `--print`, with the same command line, gives the definition, which the policy judges before bake runs (`bakescreening`, `BuildRules.check_bake`). The policy resolves relative paths against the current directory, not against a bake file given with `-f` elsewhere: a known gap.
- Tests: unit `test_docker_bake.py::test_what_a_build_could_reach_on_the_host_is_refused`, `::test_bake_runs_only_when_screening_passes`; e2e `test_e2e_docker_bake.py::test_a_target_that_reaches_the_host_is_refused`, `::test_the_command_line_is_applied_before_the_check`.

## Other projects' resources

### N1. Another project's name

```yaml
name: victim
volumes: {data: {}}
services: {app: {image: alpine, volumes: ["data:/d"]}}
```

The name decides which volumes (`victim_data`), networks and containers compose uses, replaces and, with `down -v`, removes.

- Defense: compose must have made the containers of that project name from this directory, by their `com.docker.compose.project.working_dir` label, which dockscreen checks before every compose command that acts on a project; a name the user gives with `-p` is theirs (`ProjectRules.check_project_name`). The policy refuses a volume or network with an explicit `name:` that is not `<project>_<key>`, or with `external: true` (`projectrules._check_scope`).
- Tests: unit `test_project_name.py::test_a_name_used_from_another_directory_is_refused_with_the_way_out`, `test_policy.py::test_external_and_foreign_named_volumes_and_networks_are_refused`; e2e `test_e2e_compose_project.py::test_a_name_used_by_containers_of_another_directory_is_refused`, `::test_a_name_from_the_projects_dotenv_is_checked`, `test_e2e_compose_mounts.py::test_a_network_that_is_not_the_projects_own_is_refused`.
- Known gap: volumes and networks carry no directory label, so once a project's containers are gone, another project can take its volumes by name.

### N2. A service name that is an option

A service called `--ssh` turns `docker compose build web --ssh` into a build with the user's SSH agent.

- Defense: the policy refuses names that start with `-`, and dockscreen puts `--` before the names it passes (`ProjectRules._check_service_names`).
- Tests: unit `test_policy.py::test_a_service_name_that_compose_would_read_as_an_option_is_refused`; e2e `test_e2e_compose_services.py::test_a_service_name_that_compose_would_read_as_an_option_is_refused`.

### N3. Networks off the host's NAT

A `macvlan` or `ipvlan` network puts the container on the host's LAN with an address of its own, past the host's firewall; bridge options can attach to an existing bridge.

- Defense: drivers `bridge` and `none` only, one bridge option (MTU), default IPAM (`projectrules.NETWORK_DRIVERS`).
- Tests: unit `test_policy.py::test_network_drivers_and_options`; e2e `test_e2e_compose_mounts.py::test_a_network_that_is_not_the_projects_own_is_refused` (another driver).

## dockscreen itself

### D1. Forged output

A mount source, image name or service name with a newline, ANSI escapes or bidi overrides, to forge a "passed" line, hide a refusal, or inject keys into the `harden` override the user saves.

- Defense: dockscreen escapes everything from a project or image before printing it (`messages.printable`); `harden` escapes comments and quotes names and keys (`compose_harden._render`).
- Tests: unit `test_text.py::test_refusal_output_cannot_forge_lines_or_move_the_cursor`, `::test_newline_in_untrusted_text_cannot_leave_the_patch_comment`, `::test_patch_quotes_unusual_keys`; e2e `test_e2e_escaping.py::test_a_mount_source_cannot_forge_a_verdict`, `::test_bidi_overrides_are_shown_as_text`.

### D2. The config, or the docker binary, from the project

dockscreen trusts the config file completely, and finds the real docker on `PATH`.

- Defense: the config file and every directory above it must be owned by the user or root and writable by nobody else; dockscreen ignores a relative `XDG_CONFIG_HOME`; `docker` in the config must be absolute; dockscreen skips empty and relative `PATH` entries, with a warning (`host.config`, `host.runtime`). Strict modes cannot stop an agent that runs as the user; only a root-owned file in `/etc` does.
- Tests: unit `test_config.py::test_strict_modes_refuse_what_someone_else_could_have_written`, `test_runtime.py::test_empty_and_relative_entries_are_never_searched`; e2e `test_e2e_dispatch.py::test_a_config_file_others_could_have_written_stops_everything`, `::test_empty_and_relative_path_entries_are_skipped_and_warned_about`.

### D3. Another daemon

`-H`, `--context`, `DOCKER_HOST` or a non-default context: ids and paths of this host mean nothing on another daemon.

- Defense: refused (`docker.is_remote`, `Policy.check_daemon`).
- Tests: unit `test_docker_cli.py::test_remote_daemons_are_refused`; e2e `test_e2e_docker_run.py::test_a_daemon_that_may_not_be_this_hosts_is_refused`.

## Not covered on purpose

- Requests on your own command line (`docker run -v /:/mnt --privileged`): you can call docker directly anyway. `audit` points it out, and `--strict-screen` refuses it.
- Clients that use the docker socket directly: IDEs, scripts, other tools.
- Network exposure: `ports`, `extra_hosts`, `dns`.
- `${VAR}` interpolation that copies values from your shell into the config.

## Missing tests

- H3: `include` and `extends` of outside or remote files; `subpath` with `..`.
- P2: unit tests for `uts`, `userns_mode` and `cgroup` (e2e covers them).
- N3: IPAM drivers and bridge options.
- T1: an e2e test that actually moves a tag between check and run.
