# dockscreen scenarios

Audience: people who change dockscreen or review its security. Each scenario is a way a hostile compose project or image could try to get past the policy in dockscreen's `docs/design.md`, written so that it can become a test.

Status values: **tested** (a test exists that I know of), **mentioned** (the term appears in the source but I have not confirmed the behaviour), **no test found** (no hit in `tests/`). The status comes from a grep of `src/` and `tests/`, not from reading the checks, so confirm before relying on it. A status that names a test comes from the change that added the scenario. Where a scenario depends on how the docker daemon behaves, that is said, and was not run against a daemon.

## Bind mount

Goal of the attacker: a container that can read or write host paths outside the project directory (`/`, `/etc`, `$HOME`, the docker socket). Dockscreen checks the config that `docker compose config` prints, so the first scenarios depend on the check being applied to that resolved form and to real paths, not to the text in the file.

### B1. Symlink inside the project

The project contains `data -> /etc` and the service mounts `./data:/x`. The mount source is inside the project as text. Docker follows the symlink when it creates the container.

- Expected: refused, because the real path is outside the project and `mount_dirs`.
- Check: the path is resolved with symlinks before it is compared.
- Status: mentioned (`symlink`, `realpath`; tests exist).

### B2. Symlink swapped between audit and start

A container from an earlier `up` has the project mounted read-write. It replaces a directory, or a symlink target, after the audit passed and before docker creates the next container.

- Expected: either refused, or documented as out of scope with the reason.
- Check: whether the generated, checked file only names paths that cannot change under it, and whether the audit-to-create gap is closed for bind mount sources (design.md covers images and the config file, not mount sources).
- Status: no test found. Open question, not a known bug.

### B3. Named volume that is a bind mount

```yaml
volumes:
  host:
    driver: local
    driver_opts: {type: none, o: bind, device: /}
services:
  app:
    volumes: ["host:/mnt"]
```

The service uses a named volume, so there is no bind mount in `volumes:` to inspect.

- Expected: refused, as a bind mount of `/`.
- Variants: `device: /etc`, `o: bind,ro`, `type: nfs` or `cifs` with a host address, a different volume `driver`.
- Status: mentioned (`driver_opts`; a test exists).

### B3a. A tmpfs volume with the bind flag

```yaml
volumes:
  d:
    driver_opts: {type: tmpfs, device: /etc, o: bind}
services:
  app:
    volumes: ["d:/h"]
```

The volume says `type: tmpfs`, which is harmless, but the local driver passes `type`, `device` and `o` to mount(2), and the kernel ignores the filesystem type when the bind flag is set. The container gets the host's `/etc`. Unverified on a daemon; the policy refuses it whatever the daemon does.

- Expected: refused.
- Check: a tmpfs volume has no device (or `tmpfs`) and no `bind` or `rbind` in `o`, however it is spelled (`Bind`, `size=1m, bind`). `bind` without a device is refused. `driver_opts` keys other than `type`, `device` and `o` are refused.
- Variants: `o: rbind`, `device: /etc` without `o`, an extra key such as `size`.
- Status: tested (`tests/test_policy.py::test_a_tmpfs_volume_cannot_be_made_a_bind_mount_of_a_host_path`, `::test_volume_driver_opts_are_an_allowlist_and_bind_needs_a_device`).

### B4. Explicit volume name of an existing volume

`volumes: {host: {name: hostroot}}`, where a volume `hostroot` was created earlier with the options of B3, by hand or by another project. Compose normally prefixes the project name, but `name:` turns that off.

- Expected: refused, because the volume belongs to another project or is not created by this one.
- Variant: `external: true`.
- Status: mentioned (`name:`; tests exist).

### B5. Paths that mean the root without being `/` or `/etc`

| Source | Why it matters |
|---|---|
| `/proc/1/root`, `/proc/self/root` | the host root through procfs |
| `/var/run/docker.sock`, `/run/docker.sock` | control of the daemon, which is root on the host |
| `/etc/..`, `//`, `/./` | non-normalised spellings of `/` |
| `~`, `~/.ssh` | expanded to the caller's home directory by compose |
| `/dev`, `/sys`, `/run` | devices and runtime state |
| `/home/<other user>` | another account's files |

- Expected: all refused, since none is inside the project or `mount_dirs`. The rule should be "outside the project", not a list of dangerous names.
- Status: `docker.sock` tested; `/proc` has one source hit and no test.

### B6. Source built from interpolation

`volumes: ["${SRC:-/}:/mnt"]`, with `SRC` set or unset in `.env`, in an `env_file`, in your shell, or by a `COMPOSE_FILE` / `COMPOSE_` variable in `.env`.

- Expected: refused after interpolation. A value that comes from your shell still has to pass.
- Check: dockscreen sets `UID` and `GID` itself; nothing else changes what the checked file says between audit and run.
- Status: no test found by name; the design (checked config written to a file and given to compose as its only input) addresses it.

### B7. Host reads and mounts that are not `volumes:`

Each of these gives a container or a build host content from outside the project, without a `volumes:` entry.

| Mechanism | Example |
|---|---|
| `secrets`, `configs` | `file: /etc/shadow` |
| `env_file` | `/etc/environment`, `~/.aws/credentials` |
| `build` | `context: /`, `dockerfile: /etc/x`, `additional_contexts`, `secrets`, `ssh` |
| `develop.watch` | `path:` outside the project, with `action: sync` |
| `devices` | `/dev/sda` |
| `volumes_from` | another container's mounts |
| `volume.subpath` | a path into a volume, which may include `..` |
| `include`, `extends` | a compose file outside the project, or a remote git or OCI source |

- Expected: refused, as the README states for files "outside the project directory".
- Status: `additional_contexts`, `watch`, `include` tested or mentioned; `subpath` and `extends` have no test found.

### B8. Service hidden behind a profile

A service with `profiles: [debug]` is absent from the default config. `compose run debug` activates the profile for that service.

- Expected: the audit looks at the services the command will start, including the one named on the command line.
- Status: no test found (`profiles` has no hits in `tests/`).

### B9. Parser differences

YAML anchors and merge keys (`<<:`), duplicate keys, and unusual tags can be read differently by two parsers.

- Expected: no effect, because dockscreen does not parse the file; compose does, and dockscreen reads compose's output.
- Check: the generated file is read back through `docker compose config` and compared with what was checked (the README says it is).
- Status: by design.

### B10. Not covered on purpose

- Mounts chosen on your own command line (`docker run -v /:/mnt`). `dockscreen audit` points them out, and `--strict-screen` fails the audit for them.
- Clients that use the docker socket directly, such as IDEs and scripts. A PhpStorm docker integration bypasses the wrapper.
- Network exposure (`ports`, `extra_hosts`, `dns`).

## Users and ids

Goal of the attacker: a container that runs as root, or as an id that owns files on the host, although the project chose neither.

### U1. User check skipped because the mounts are hidden in a volume

```yaml
volumes:
  d:
    driver_opts: {type: none, o: bind, device: /project/data}
services:
  app:
    user: "5000:5001"
    volumes: ["d:/h"]
```

The service has no bind mount of its own, so it counts as having no host mounts, and an id that is not root, not local and not in a subordinate range passes. The volume is a bind mount of the project's files, where the id decides what the container can write.

- Expected: the id rules for host mounts apply: `5000:5001` is refused, as it would be with a bind mount.
- Check: whether a service has host mounts is worked out from the whole config. A mount of a volume whose `driver_opts` name a device or mount options counts; a plain tmpfs volume does not.
- Variants: a volume with `o: bind` and no device; the same through `compose run`, `harden` and the image decision for a service that sets no user.
- Not covered: `docker run` and `docker start`, where a volume is only a name (see the open list in `security-review.md`).
- Status: tested (`tests/test_policy.py::test_a_named_volume_set_up_as_a_bind_mount_reaches_host_files`, `::test_the_id_rules_for_host_mounts_apply_to_a_service_of_a_bind_volume`).

### U2. A numeric `group_add` that the daemon reads as a group name

```yaml
services:
  app:
    user: "65534:65534"
    group_add: ["65534"]
```

with an image whose `/etc/group` has `65534:x:0:` before the real entry. An older daemon looks the argument up by name first and then by number, so the container gets supplementary gid 0. Current moby matches numbers by number only. Unverified on a daemon. Dockscreen can neither pin `group_add` nor read the group file of a service that sets `user:`.

- Expected: refused, whatever the value is.
- Check: `group_add` is a forbidden service key; `harden` removes it with a `!reset`, and does not resolve its names.
- Variants: a name (`docker`), `0`, an id in the nobody range.
- Not covered on purpose: `docker run --group-add`, which is on your command line; `audit` reports it.
- Status: tested (`tests/test_policy.py::test_group_add_is_refused_whatever_it_names`, `tests/test_patch.py`).

### U3. An id that an older daemon wraps or clamps

`user: "4294967296:65534"` with a matching passwd line, `user: "99999999999999999999:65534"`, or an image `USER` of these. An older daemon converts the id to 32 bits when it builds the OCI spec, which gives uid 0, and `4294967296+1000` gives your own uid; an overflowing number is read as a name and looked up in the image's passwd, where the image can define it as uid 0. Current moby rejects both. Unverified on an older daemon.

- Expected: refused, with or without host mounts.
- Check: any id above 2147483647 is refused in `idrules.Rules.problem`, which every id from a project, a hook or an image passes. An allowed id is exempt, because the config file chose it.
- Variants: the uid, the gid, a supplementary gid of the image, `2147483648`, `4294967296`, `10**20`; `2147483647` is not refused for its size.
- Status: tested (`tests/test_idrules.py::test_ids_above_the_largest_docker_accepts_are_refused_with_or_without_mounts`).

## Build

### K1. `docker buildx bake` reads the project's files unscreened

`docker buildx bake` reads `docker-bake.hcl`, or a compose file with `x-bake`, which the project controls, and builds without the checks that `docker compose build` gets.

```hcl
target "app" {
  context  = "/"
  output   = ["type=local,dest=/etc"]
  secret   = ["id=k,src=/home/me/.ssh/id_rsa"]
  ssh      = ["default"]
  network  = "host"
}
```

- Expected: refused, and nothing builds.
- Check: `docker buildx bake --print` with the same arguments gives the definition, with the command line applied, and builds nothing; `bake.check_definition` screens that. Refused: a context, dockerfile or named context outside the current directory; a network other than `none`; `entitlements` and `ssh`; an `output` that is not an image, registry, docker or cacheonly output without a `dest`; a `cache-to` that is not `inline` or `registry`; a local `cache-from` outside the project; a secret that is not a file inside the project, or is copied from a variable; any key it does not know. If `--print` fails, bake does not run.
- Variants: `--set` and `--push` on the command line, which are in the printed definition; `--print` and `--help` pass through.
- Not covered on purpose: `buildx build` and `docker build`, whose Dockerfile cannot reach the host without options that your command line gives. Relative paths are resolved against the current directory, not the directory of a bake file given with `-f`.
- Status: tested (`tests/test_bake.py`). The `--print` format was checked against one real project, not against every key.

## Project name and arguments

### N1. A project that takes the name of another project

```yaml
name: victim
volumes:
  data: {}
services:
  app:
    image: alpine
    volumes: ["data:/d"]
```

The name decides which volumes (`victim_data`), networks and containers compose uses, replaces and removes. The hostile project reads and writes the victim's volume, replaces a service of the same name, joins its network, and makes `down -v` or `--remove-orphans` delete its data.

- Expected: refused when containers of a project called `victim`, running or stopped, were made from another directory, or have no directory label.
- Check: `screen.name_conflicts` compares the `com.docker.compose.project.working_dir` label of those containers with this project's directory. It runs with the other checks for `up`, `create`, `run`, `watch`, `scale` and `alpha`, and alone before `down`, `rm`, `stop`, `kill`, `restart`, `start`, `pause` and `unpause`. If docker cannot say, a project is refused.
- Variants: the name comes from `COMPOSE_PROJECT_NAME` in the project's `.env`, which is the project's choice and is checked; `-p NAME` and `COMPOSE_PROJECT_NAME` in your real environment are your choice and are not.
- Not covered: volumes and networks carry no directory label, so a project whose containers are all gone can still have its volumes taken over by name.
- Status: tested (`tests/test_project_name.py`). The label and the `docker ps` format were not run against a daemon.

### N2. A service name that is an option

```yaml
services:
  --ssh:
    image: alpine
    build: .
```

The compose spec allows a name that starts with `-`. Passed as an argument, `--ssh` becomes `docker compose build --ssh default`, which forwards your SSH agent (a `build.ssh` key is refused by the policy).

- Expected: refused, for `up`, `build` and `bake` alike.
- Check: a service name that starts with `-` is refused in `check_config` and `check_build_config`; the pulls and builds of images put `--` before the service names. `docker compose --dry-run pull -- -dash` was tried against a real compose.
- Status: tested (`tests/test_policy.py::test_a_service_name_that_compose_would_read_as_an_option_is_refused`, and the pull and build commands in `tests/test_composeimages.py`).

## Priorities

Add tests for B2, B5 (`/proc/*/root`), B7 (`subpath`, `extends`) and B8 first: they are where the grep found the least. U1 to U3 and K1 depend on the daemon's behaviour; an integration test against a real daemon would settle them.
