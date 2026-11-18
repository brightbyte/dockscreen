# Security review: open findings

Audience: whoever fixes the findings below. This review leaves out fixed findings, and orders the others by priority; no high-priority findings are open.

Threat model: the compose project and the image are untrusted. Usually neither is hostile, but either may be. The command line is trusted not to be malicious, but dockscreen protects the user typing it from mistakes and from tricks of the project. Running as root must be rare and opt-in; running as the invoking user must not be selectable by a project or by an image.

Method: reading the source. "Code confirmed" means the reviewer re-read the dockscreen side. The behaviour of docker, moby, runc, the kernel, compose and buildx comes from reading or memory, and the review marks it "unverified" where a finding depends on it. A test that runs `docker compose config` and `docker buildx bake --print` on real projects would settle most of those.

## Medium

### 1. An `include:` entry's `env_file` and `extends.file` are invisible in the `config` output

Host file contents can flow into values such as `image:`, which docker sends to the registry at pull time. The policy covers the `env_file` of services, but it does not cover these two inputs.

Fix: refuse them in the raw config, or document them as out of scope.

### 1a. With the containerd image store, a local name proves a pull

`sections.section_for` takes an entry in `RepoDigests` for the repository as proof that the image was pulled from there. With docker's containerd image store, `RepoDigests` lists a digest under every name the image has. So `docker tag`, or a build with `image: mariadb:x`, gives the image such a digest. A project can build an image under the name of a repository that the config file has a section for. A second service, which does not build, can then run that image as the section's user, with host mounts.

Seen in the end-to-end tests, for a tagged and for a built image: `test_e2e_compose_images.py` and `test_e2e_docker_audit.py` have the scenarios, marked as expected failures until this is fixed. The classic image store does not do this (unverified).

Fix: a proof that a local name cannot fake, for example that the digest is known to the registry, or not trusting `RepoDigests` with the containerd store.

## Low

Ordered by the likelihood that the problem matters, then by the cost of the fix.

### 2. Ctrl-C and SIGTERM on `docker run` leave the container running

`Docker.start` waits with `subprocess.run`: Ctrl-C kills the `docker start --attach` client after 0.25 s and shows a traceback; SIGTERM orphans the child. `Docker.run_child` already forwards signals; reuse that forwarding.

### 3. `docker run` and `docker start` do not see a bind-backed named volume

In a project, a named volume whose `driver_opts` bind a host path counts as a host mount. For a container, the volume is only a name, so dockscreen does not count a volume that someone created that way earlier, and the id rules for containers without host mounts apply.

### 4. `docker run` recreates the container by image name, not id

`commands.docker_run.gate`: `create` for the fallback uses the name, not the id, so a tag that moves between the two creates applies the pinned user of image A to image B. `decisions.changes` already pins the id. The attack needs a concurrent actor.

### 5. `annotations` is allowed unchecked

`servicerules.HARMLESS_SERVICE_KEYS`. `run.oci.keep_original_groups` under crun keeps the runtime's supplementary groups. The finding depends on the daemon's runtime. Drop it from the harmless list or refuse `run.oci.*`.

### 6. Symlink swap between check and mount

`is_inside` resolves symlinks for the check only; docker resolves them again at start. With a read-write project mount, service A can re-point `./x` before service B (`depends_on: A`) mounts it. The attack needs `--allow-me` or a world-writable project directory. Fix: refuse bind sources whose `realpath` differs from their normalized path.

### 7. `additional_contexts: oci-layout://…` counts as a remote URL

`buildrules._is_host_path` treats such a context as a remote URL, but buildx reads a local layout. Allowlist the URL schemes. The same applies to the contexts of a bake definition.

### 8. An `ipam` subnet can overlap the LAN

The policy checks the `ipam` keys and driver, not the subnets, so a project can declare a network that takes over routes to hosts on the LAN.

### 9. `docker buildx bake` resolves relative paths against the current directory

The policy checks a bake file given with `-f` from another directory against the wrong base.

### 10. Commands that start containers or build without going through dockscreen

dockscreen passes `docker sandbox run`, `docker model run`, swarm `service create` and `stack deploy` through unchecked, and does not screen `buildx build` and `docker build` either: their Dockerfile cannot reach the host without options, and the command line is trusted.

### 11. `harden` maps a mount source `/` to `./`

`compose_harden._placeholder_source`: the patch would mount the project read-write although its note says "compose creates empty". The user reviews the patch before saving it, and `up` checks it again.

### 12. `docker.context()` ignores `--config`

`docker --config ~/other run img` with a remote `currentContext` there passes the remote check. Only a mistake can trigger this.

### 13. Unknown value-taking global options fail open

`docker compose --newopt val up` makes `val` the subcommand and forwards `up` unscreened. No current trigger; the docker option set looks complete.

### 14. Config trust

`config._check_strict_modes` walks the realpath chain only, not the directory that holds a symlinked path. Project sections match by cwd prefix (documented). `/etc/subuid` is read directly, so NSS subid sources are not covered.

### 15. Uncaught exceptions end in a traceback

`getpwnam` with a NUL, `getgrgid` with a huge id, `int()` on more than 4300 digits; `screen.containerscreening.create` catches only `DockerError`, `ValueError` and `KeyError` and leaves the created container behind for other exceptions.

### 16. `messages.printable_text` does not escape `\`

A literal `\x0a` in a project name looks like an escape; invisible printable characters (U+2800, U+3164) pass. The verdict line cannot be forged inside project strings, because every sink escapes. Raw docker, pull and build output can print `[dockscreen] ✔ audit passed` before the real verdict, and container output follows it; this is inherent in passing output through.

### 17. `imageuser.resolve` reports supplementary groups even when the group is given explicitly

Moby does not report them. This is harmless on `run` and compose; a spurious refusal on `start`.

## Accepted limits

Not defects to fix; the design records them as known gaps or as choices.

- `start` and `restart` trust a container whose user differs from its image's, as `run --user` is trusted: dockscreen cannot tell a container made on a command line from a container that a project's script made. They do not examine `HostConfig` (privileged, binds, devices). For an image's own user, the daemon resolves the name at start. So the safety rests on `imageuser` reading ids as the daemon does. `restart` has a window: after the check, a running container with a writable `/etc/passwd` can still change the result.
- `docker run --group-add` is trusted like the rest of the command line, and `audit` reports it. An older daemon resolves a numeric value as a group name from the image first.
- The project mount is read-write, so a container can write files that run on the host, such as `.git/hooks`, as whatever user it runs as.
- The project name check compares containers only, because volumes and networks carry no directory label. Once a project's containers are all gone, another project can take over its volumes by name. A name given with `-p` or `COMPOSE_PROJECT_NAME` in the environment is the user's choice and is not checked.
- A daemon's behaviour on ids above 2147483647, on `group_add` and on `type: tmpfs` volumes with `bind` is unverified; the policy refuses them whatever the daemon does.

## Checked and fine

- The policy refuses service keys outside the allowlist (`provider`, `models`, `use_api_socket`, `credential_spec`, `extends`, `entitlements`, `cache_to`, `cache_from`); it ignores `x-` fields except in `build`; compose resolves anchors and merge keys before the check.
- The policy refuses `cap_add`, `devices`, `privileged`, `gpus`, `cgroup_parent`, `device_cgroup_rules` and `group_add`; `cap_drop` must include `ALL`; `security_opt` must be exactly no-new-privileges; `pid`, `ipc`, `uts`, `userns_mode`, `cgroup` and `network_mode` may not be `host` or `container:`; `runtime` may only be `runc`; the policy checks hook keys.
- Bind sources, local volume `device`, secrets and configs `file`, `env_file`, `label_file`, `develop.watch.path`, build contexts and dockerfiles go through `is_inside` with `realpath`; a dangling symlink resolves to its target; a NUL byte is a refusal. Volume `driver_opts` are an allowlist, and tmpfs volumes cannot bind.
- The policy refuses ids above 2147483647, with or without host mounts.
- dockscreen compares the generated compose file with compose's reading of it, before any pull or build; it writes the file in a private directory (0700) as an exclusive 0600 file, and pins services whose image it looked at to the image id.
- The generated file replaces `-f`, `--project-directory`, `--project-name` and `-p` from the command line.
- `imageuser.py` matches moby/sys/user `main` for line splitting, whitespace, `atoi`, zero-filling, first match, numeric specs, NUL, duplicates and `a:b:c`.
- Numeric pinning covers `run`, compose `up`/`create` and `compose run`; `runargs` handles `--user=`, `-u` and clustered `-u`; `containerscreening._verify_split` catches a misread command line; the policy refuses a uid without a group.
- Image sections need a RepoDigests match on the image id; built and retagged images match nothing; sections cannot cross projects.
- `--skip-screening`, `--allow-me`, `--strict-screen` and `--helpful` come only from argv before the subcommand; dockscreen refuses `--strict-screen` with anything but `audit`.
- Every `Docker` call uses `--` before container ids and image names; dockscreen reads image files through the tar stream, capped at 1 MiB, and fails closed.
- Finding the real docker skips empty and relative `PATH` entries and the wrapper itself; without a real docker, dockscreen stops instead of running plain `docker`. dockscreen warns about empty or relative entries, since docker and compose look up their own helpers on `PATH`.
- The policy screens `docker buildx bake` on the definition `--print` gives.
