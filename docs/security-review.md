# Security review: open findings

Audience: whoever fixes the findings below. Fixed findings are not listed. Findings are ordered by priority; there are no high ones open.

Threat model: the compose project and the image are untrusted. Usually neither is hostile, but either may be. The command line is trusted not to be malicious, but the person typing it is protected from mistakes and from being tricked by the project. Running as root must be rare and opt-in; running as the calling user must not be selectable by a project or image.

Method: reading the source. "Code confirmed" means the dockscreen side was re-read. The behaviour of docker, moby, runc, the kernel, compose and buildx comes from reading or memory and is marked "unverified" where a finding depends on it. A test that runs `docker compose config` and `docker buildx bake --print` on real projects would settle most of those.

## Medium

### 1. An `include:` entry's `env_file` and `extends.file` are invisible in the `config` output

Host file contents can flow into values such as `image:` and be sent at pull time. The `env_file` of services is covered; these two are not.

Fix: refuse them in the raw config, or document as out of scope.

## Low

Ordered by how likely the problem is to matter, then by how cheap the fix is.

### 2. Ctrl-C and SIGTERM on `docker run` leave the container running

`Docker.start` uses `subprocess.call`: Ctrl-C kills the `docker start --attach` client after 0.25 s and shows a traceback; SIGTERM orphans the child. `Docker.run_child` already forwards signals; reuse it.

### 3. `docker run` and `docker start` do not see a bind-backed named volume

In a project, a named volume whose `driver_opts` bind a host path counts as a host mount. For a container, the volume is only a name, so a volume that was created that way earlier is not counted, and the id rules for containers without host mounts apply.

### 4. `docker run` recreates the container by image name, not id

`gate.py:96, 148`: `create` for the fallback uses the name, not the id, so a tag that moves between the two creates applies the pinned user of image A to image B. `composeimages.finalize` already pins the id. Needs a concurrent actor.

### 5. `annotations` is allowed unchecked

`policy.HARMLESS_SERVICE_KEYS`. `run.oci.keep_original_groups` under crun keeps the runtime's supplementary groups. Depends on the daemon's runtime. Drop it from the harmless list or refuse `run.oci.*`.

### 6. Symlink swap between check and mount

`is_inside` resolves symlinks for the check only; docker resolves them at start. With a read-write project mount, service A can re-point `./x` before service B (`depends_on: A`) mounts it. Needs `--allow-me` or a world-writable project directory. Fix: refuse bind sources whose `realpath` differs from their normalized path.

### 7. `additional_contexts: oci-layout://…` counts as a remote URL

`policy._is_host_path` treats it as one; buildx reads a local layout. Allowlist the URL schemes. The same applies to the contexts of a bake definition.

### 8. An `ipam` subnet can overlap the LAN

The policy checks the `ipam` keys and driver, not the subnets, so a project can declare a network that takes over routes to hosts on the LAN.

### 9. `docker buildx bake` resolves relative paths against the current directory

A bake file given with `-f` from another directory is checked against the wrong base.

### 10. Commands that start containers or build without going through dockscreen

`docker sandbox run`, `docker model run`, swarm `service create` and `stack deploy` are passed through unchecked. `buildx build` and `docker build` are not screened either: their Dockerfile cannot reach the host without options, and the command line is trusted.

### 11. `harden` maps a mount source `/` to `./`

`autofix._placeholder_source`: the patch would mount the project read-write although its note says "compose creates empty". The patch is reviewed before it is saved, and `up` checks it again.

### 12. `docker.context()` ignores `--config`

`docker --config ~/other run img` with a remote `currentContext` there passes the remote check. Mistake class only.

### 13. Unknown value-taking global options fail open

`docker compose --newopt val up` makes `val` the subcommand and forwards `up` unscreened. No current trigger; the docker option set looks complete.

### 14. Config trust

`config._strict_modes` walks the realpath chain only, not the directory that holds a symlinked path. Project sections match by cwd prefix (documented). `/etc/subuid` is read directly, so NSS subid sources are not covered.

### 15. Uncaught exceptions end in a traceback

`getpwnam` with a NUL, `getgrgid` with a huge id, `int()` on more than 4300 digits; `gate.py:152-159` catches only `DockerError`, `ValueError` and `KeyError` and leaves the created container behind for others.

### 16. `messages.printable` does not escape `\`

A literal `\x0a` in a project name looks like an escape; invisible printable characters (U+2800, U+3164) pass. The verdict line cannot be forged inside project strings, because every sink escapes. Raw docker, pull and build output can print `[dockscreen] ✔ audit passed` before the real verdict, and container output follows it; inherent to passing output through.

### 17. `imageuser.resolve` reports supplementary groups even when the group is given explicitly

Moby does not. Harmless on `run` and compose; a spurious refusal on `start`.

## Accepted limits

Not defects to fix; the design records them as known gaps or as choices.

- `start` and `restart` trust a container whose user differs from its image's, as `run --user` is trusted: a container made on a command line cannot be told from one a project's script made. `HostConfig` (privileged, binds, devices) is not examined. For an image's own user, the daemon resolves the name at start, so the safety rests on `imageuser` reading ids as the daemon does; `restart` has a window in which a running container with a writable `/etc/passwd` can change the result after the check.
- `docker run --group-add` is trusted like the rest of the command line, and `audit` reports it. An older daemon resolves a numeric value as a group name from the image first.
- The project mount is read-write, so a container can write files that run on the host, such as `.git/hooks`, as whatever user it runs as.
- The project name check compares containers only: volumes and networks carry no directory label, so a project whose containers are all gone can still have its volumes taken over by name. A name given with `-p` or `COMPOSE_PROJECT_NAME` in the environment is the person's choice and is not checked.
- A daemon's behaviour on ids above 2147483647, on `group_add` and on `type: tmpfs` volumes with `bind` is unverified; the policy refuses them whatever the daemon does.

## Checked and fine

- Service keys outside the allowlist are refused (`provider`, `models`, `use_api_socket`, `credential_spec`, `extends`, `entitlements`, `cache_to`, `cache_from`); `x-` fields are ignored except in `build`; anchors and merge keys are resolved before the check.
- `cap_add`, `devices`, `privileged`, `gpus`, `cgroup_parent`, `device_cgroup_rules` and `group_add` are refused; `cap_drop` must include `ALL`; `security_opt` exactly no-new-privileges; `pid`, `ipc`, `uts`, `userns_mode`, `cgroup`, `network_mode` refuse `host` and `container:`; `runtime` only `runc`; hook keys checked.
- Bind sources, local volume `device`, secrets and configs `file`, `env_file`, `label_file`, `develop.watch.path`, build contexts and dockerfiles go through `is_inside` with `realpath`; a dangling symlink resolves to its target; a NUL byte is a refusal. Volume `driver_opts` are an allowlist, and tmpfs volumes cannot bind.
- Ids above 2147483647 are refused with or without host mounts.
- The generated compose file is checked against what compose reads back from it, before any pull or build; it is written in a private directory (0700) with an exclusive 0600 file; services whose image was looked at are pinned to the image id.
- `-f`, `--project-directory`, `--project-name`, `-p` from the command line are replaced by the generated file.
- `imageuser.py` matches moby/sys/user `main` for line splitting, whitespace, `atoi`, zero-filling, first match, numeric specs, NUL, duplicates and `a:b:c`.
- Numeric pinning covers `run`, compose `up`/`create` and `compose run`; `runargs` handles `--user=`, `-u` and clustered `-u`; `gate._verify_split` catches a misread command line; a uid without a group is refused.
- Image sections need a RepoDigests match on the image id; built and retagged images match nothing; sections cannot cross projects.
- `--skip-screening`, `--allow-me`, `--strict-screen` and `--helpful` come only from argv before the subcommand; `--strict-screen` with anything but `audit` is refused.
- Every `Docker` call uses `--` before container ids and image names; image files are read through the tar stream, capped at 1 MiB, fail closed.
- Finding the real docker skips empty and relative `PATH` entries and the wrapper itself; without one, dockscreen stops instead of running plain `docker`. Empty or relative entries are warned about, since docker and compose look up their own helpers on `PATH`.
- `docker buildx bake` is screened on the definition `--print` gives.
