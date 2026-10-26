# dockscreen scenarios

Audience: people who change dockscreen or review its security. Each scenario is a way a hostile compose project or image could try to get past the policy in dockscreen's `docs/design.md`, written so that it can become a test.

Status values: **tested** (a test exists that I know of), **mentioned** (the term appears in the source but I have not confirmed the behaviour), **no test found** (no hit in `tests/`). The status comes from a grep of `src/` and `tests/`, not from reading the checks, so confirm before relying on it.

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

## Priorities

Add tests for B2, B5 (`/proc/*/root`), B7 (`subpath`, `extends`) and B8 first: they are where the grep found the least.
