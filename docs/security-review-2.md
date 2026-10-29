# Security review, round 2: dockscreen at 8bea9c6

Audience: whoever fixes the findings below. Follows [security-review.md](security-review.md) (round 1, at a32a493).

Threat model: the compose project and the image are hostile. The command line is trusted not to be malicious, but the person typing it is protected from mistakes and from being tricked by the project. Running as root must be rare and opt-in; running as the calling user must not be selectable by a project or image.

Method: three read-only reviews of the source, one per area (compose path; who a container runs as; docker command surface), then the main claims below were re-read in the code. Nothing was executed and docker was not run. "Code confirmed" means the dockscreen side was re-read; behaviour of docker, moby, runc, the kernel and compose is from reading or memory and is marked "daemon side unverified" where a finding depends on it. A test that passes `docker compose config` on a real project would settle most of those.

## Round 1 findings

| # | Finding | Status |
|---|---------|--------|
| 1 | Compose interpolates the generated config twice | Fixed: `composeimages.verify_round_trip` refuses unless `config` of the generated file equals the checked config, before any pull or build |
| 2 | Python user lookup differs from moby | Fixed: parser follows moby (`imageuser.py`); every accepted identity is pinned as `uid:gid`. Residual: see R2-3, R2-4 |
| 3 | `--user 1000` lets the image pick the group | Fixed: `hostusers.require_numeric`, `runargs` |
| 4 | Compose file picks "me" | Fixed: `idrules` allows the caller's ids only with `--allow-me` |
| 5 | `composerun` ignores remote daemons | Fixed: `screen.is_remote` in `composerun`. Residual: R2-17 |
| 6 | Image pinned only by tag | Fixed for services whose image was looked at: `finalize` pins the image id. `docker run` still recreates by name: R2-9 |
| 7 | `docker create` without `--` | Fixed. The same mistake exists for service names: R2-6 |
| 8 | Supplementary groups reported for an explicit group | Open, harmless on `run` and compose; a spurious refusal on `start` |
| include/extends `env_file` | Partly fixed; the `include:` entry's own `env_file` and `extends.file` are invisible in `config` output: R2-12 |
| project name reaches other projects' volumes | Open: R2-5 |

## High

### R2-1. `type: tmpfs` with `o: bind` makes a named volume a bind mount of any host path

`policy.check_driver_opts` returns `[]` for `type: tmpfs` before it looks at `device`, and `o` is never inspected.

```yaml
volumes: {d: {driver_opts: {type: tmpfs, device: /etc, o: bind}}}
services: {x: {volumes: ["d:/h"]}}
```

Code confirmed. The existing test covers only `device: "tmpfs"`. Daemon side unverified: the local driver passes `type`, `device` and `o` to mount(2), and the kernel ignores the filesystem type when `MS_BIND` is set.

Fix: allowlist the `driver_opts` keys. For `tmpfs`, require `device` empty or `tmpfs` and refuse `bind`/`rbind` in `o`. For other types, refuse `bind` and `rbind` in `o` unless `type` is `none` and `device` passed `is_inside_any`.

### R2-2. `group_add` with a numeric value is resolved by name by older daemons

`policy.check_group_add` accepts any gid in the nobody range, with or without host mounts. Older moby (`GetAdditionalGroups`) matched `g.Name == arg || Itoa(g.Gid) == arg`, first hit wins. An image whose `/etc/group` has `65534:x:0:` before the real entry gets supplementary gid 0. Current moby/sys matches numbers by gid only.

Code confirmed that dockscreen cannot pin `group_add` and never reads the group file for a service that sets `user:`. Daemon side unverified (depends on the daemon's vendored version).

Fix: refuse `group_add` from a project unless the config allows it, or refuse when any group in the image's `/etc/group` has a purely numeric name, or require a daemon version.

## Medium

### R2-3. Ids of 2^31 and above are accepted when there are no host mounts

`ids.parse_id` accepts any digit string, `imageuser.atoi` clamps to int64, and `idrules.Rules.problem` returns None for an unknown id unless there are host mounts. Code confirmed.

- `user: "99999999999999999999:65534"` overflows Go's `Atoi`; an older moby then treats the string as a name and looks it up in the image's passwd, where the image can define it as uid 0.
- `user: "4294967296:65534"` with a matching passwd line: an older moby converts the id with `uint32()` when it builds the OCI spec, which gives uid 0 (and `4294967296+1000` gives the caller's uid).
- The same values work as an image `USER` with a hostile passwd.

Current moby/sys rejects both (`ErrRange`, max 2^31-1). Daemon side unverified for older versions. A huge gid happens to fail closed by an accidental `OverflowError` in `grp.getgrgid`; a huge uid does not.

Fix: refuse any id above 2^31-1 in `ids.parse_id`, `Rules.problem` and `imageuser.resolve`, with or without mounts.

### R2-4. `docker start`/`restart` accepts users that were not pinned

`create` does not pin the user, so an existing container whose `Config.User` is the image's own `app` is accepted (Kind.OK) and moby resolves `app` itself at start. Safety then rests on parser parity, not on the pin. `restart` has a window in which a running container with a writable `/etc/passwd` can rewrite it after the check read it.

`imagedecision.assess` also infers `explicit` from the container: when `Config.User` differs from the image's, the user counts as chosen on the command line and nothing is checked. A container made by plain `docker create` or `compose create` with `User: root` therefore starts through `docker start`, which the docs say is checked. `HostConfig` (privileged, binds) is never examined for existing containers.

Code confirmed (Kind.EXPLICIT branch). Fix: accept an inferred `explicit` only when `Config.User` is numeric `uid:gid`; document the `HostConfig` gap, or check it.

This interacts with the `check_existing` change in 28999f8, which accepts a container already running as the pinned numeric user: that part is sound, since it compares numbers.

### R2-5. The project name chosen by the project reaches other projects' volumes and containers

`check_scope` only checks consistency with the project's own `name`. `name: victim` plus a volume `data` uses `victim_data`; `--remove-orphans`, `down -v` and `rm` act on the victim's containers. Round 1 listed this under "keep in mind"; it is still open and not in design.md's known gaps. Code confirmed.

Fix: refuse a `name:` that differs from the directory-derived default unless `-p` was given on the command line.

### R2-6. Service names are passed to compose without `--`

`composeimages.py:189`: `[*command, subcommand, *names]`. The compose spec allows a leading `-` in a service name, so `--ssh` becomes `docker compose build --ssh default`, which forwards the SSH agent (refused for `build.ssh` by policy). Code confirmed; unverified whether compose-go accepts such names.

Fix: `--` before `*names`, or refuse names starting with `-` in `check_config`.

### R2-7. A named volume with bind `driver_opts` is not counted as a host mount

`policy.has_host_mounts` looks at the service's own keys only. With `volumes: {d: {driver_opts: {type: none, o: bind, device: <project>/data}}}` and `user: "4242:4242"`, `mounts` is False, so any id that is not 0, not local and not in subuid passes. `composeimages.decide` uses the same function. Code confirmed.

Fix: compute host-mount status from the whole config; a volume whose `driver_opts` carry `device` or `o` is a host mount.

### R2-8. `docker buildx bake`, `buildx build` and `docker build` are not screened

`docker_cli.GATED` is `run create start restart exec audit`. `compose build` and `compose bake` get build checks; plain `docker buildx bake` reads the same hostile files without them, and `docs/design.md` says bake "can write to the host". The same applies to plugin commands that start containers (`docker sandbox run`, `docker model run`) and to swarm `service create` / `stack deploy`. Code confirmed (pass-through); whether a given buildx version writes to the host without `--allow` is unverified.

Fix: gate `buildx bake`, `buildx build` and `build` with `check_build_config`, or print a "not screened" notice; decide explicitly for the rest.

## Low

- **R2-9. `docker run` recreates the container by image name, not id.** `gate.py:96, 148`: `create` for the fallback uses the name, not the id, so a tag that moves between the two creates applies the pinned user of image A to image B. `composeimages.finalize` already pins the id. Needs a concurrent actor.
- **R2-10. `annotations` is allowed unchecked** (`policy.HARMLESS_SERVICE_KEYS`). `run.oci.keep_original_groups` under crun keeps the runtime's supplementary groups. Depends on the daemon's runtime. Drop it from the harmless list or refuse `run.oci.*`.
- **R2-11. Symlink swap between check and mount.** `is_inside` resolves symlinks for the check only; docker resolves them at start. With a read-write project mount, service A can re-point `./x` before service B (`depends_on: A`) mounts it. Needs `--allow-me` or a world-writable project directory. Fix: refuse bind sources whose `realpath` differs from their normalized path.
- **R2-12. `include:` entry `env_file` and `extends.file` are invisible** in the `config` output, so host file contents can flow into values such as `image:` and be sent at pull time. Refuse them in the raw config, or document as out of scope.
- **R2-13. `additional_contexts: oci-layout://…`** is treated as a remote URL by `is_host_path`; buildx reads a local layout. Allowlist the URL schemes.
- **R2-14. `harden` maps a mount source `/` to `./`** (`autofix.placeholder_source`): the patch would mount the project read-write although its note says "compose creates empty". Reviewed before saving, and `up` rechecks.
- **R2-15. Ctrl-C and SIGTERM on `docker run` leave the container running.** `Docker.start` uses `subprocess.call`: Ctrl-C kills the `docker start --attach` client after 0.25 s and shows a traceback; SIGTERM orphans the child. `composerun.run_child` already forwards signals; reuse it.
- **R2-16. Without a real docker, the wrapper execs itself forever.** `realdocker.choose` falls back to the plain name `"docker"`, which `execvp` finds on PATH, i.e. the wrapper. `DOCKER_NOT_FOUND` is never reached. Code confirmed. Return None or raise `DockerNotFound`.
- **R2-17. `docker.context()` ignores `--config`.** `docker --config ~/other run img` with a remote `currentContext` there passes the remote check. Mistake class only.
- **R2-18. Relative `PATH` entries are searched for the real docker** (`realdocker.find` skips only empty entries; `tests/test_realdocker.py:36` accepts `./docker`). Marginal: the shell would pick the same binary unless the wrapper is first.
- **R2-19. Unknown value-taking global options fail open.** `docker compose --newopt val up` makes `val` the subcommand and forwards `up` unscreened. No current trigger; the docker option set looks complete.
- **R2-20. Config trust.** `config.strict_modes` walks the realpath chain only, not the directory that holds a symlinked path. Project sections match by cwd prefix (documented). `/etc/subuid` is read directly, so NSS subid sources are not covered.
- **R2-21. Uncaught exceptions end in a traceback.** `getpwnam` with a NUL, `getgrgid` with a huge id, `int()` on more than 4300 digits; `gate.py:152-159` catches only `DockerError`, `ValueError` and `KeyError` and leaves the created container behind for others.
- **R2-22. `text.printable` does not escape `\`,** so a literal `\x0a` in a project name looks like an escape; invisible printable characters (U+2800, U+3164) pass. The verdict line cannot be forged inside project strings, because every sink escapes. Raw docker, pull and build output can print `[dockscreen] ✔ audit passed` before the real verdict, and container output follows it; inherent to passing output through.

## Checked and fine

- Service keys outside the allowlist are refused (`provider`, `models`, `use_api_socket`, `credential_spec`, `extends`, `entitlements`, `cache_to`, `cache_from`); `x-` fields are ignored except in `build`; anchors and merge keys are resolved before the check.
- `cap_add`, `devices`, `privileged`, `gpus`, `cgroup_parent`, `device_cgroup_rules` refused; `cap_drop` must include `ALL`; `security_opt` exactly no-new-privileges; `pid`, `ipc`, `uts`, `userns_mode`, `cgroup`, `network_mode` refuse `host` and `container:`; `runtime` only `runc`; hook keys checked.
- Bind sources, local volume `device` (non-tmpfs), secrets and configs `file`, `env_file`, `label_file`, `develop.watch.path`, build contexts and dockerfiles go through `is_inside` with `realpath`; a dangling symlink resolves to its target; a NUL byte is a refusal.
- `-f`, `--project-directory`, `--project-name`, `-p` from the command line are replaced by the generated file; the generated directory is 0700 and the file `O_EXCL` 0600.
- `imageuser.py` matches moby/sys/user `main` for line splitting, whitespace, `atoi`, zero-filling, first match, numeric specs, NUL, duplicates and `a:b:c`.
- Numeric pinning covers `run`, compose `up`/`create` and `compose run`; `runargs` handles `--user=`, `-u` and clustered `-u`; `verify_split` catches a misread command line.
- Image sections need a RepoDigests match on the image id; built and retagged images match nothing; sections cannot cross projects.
- `--skip-screening`, `--allow-me`, `--strict-screen` and `--helpful` come only from argv before the subcommand; `--strict-screen` with anything but `audit` is refused.
- Every `Docker` call uses `--` before container ids; image files are read through the tar stream, capped at 1 MiB, fail closed.

## Suggested order

R2-1 and R2-7 (the volume checks, one change), then R2-3 (id bound, one change in three places), R2-2, R2-4, R2-8. R2-5 needs a design decision like round 1's "me" item. R2-16 is a one-line fix worth doing with them.
