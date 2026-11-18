# Ideas for later

Audience: people who change dockscreen. These are not planned work: they are ideas worth doing once there is a need for them. Each idea says what it would add, and why it is not done yet. The gaps that dockscreen has today are in [design.md](docs/design.md#known-gaps).

## Strict screening for the remaining commands, and as a setting

`--strict-screen` treats the command line as untrusted. `audit`, `run`, `start` and `restart` then refuse each request that a compose project or an image may not make, and so does `compose run` for its options. `create` and `buildx bake` accept the option. Every other subcommand refuses it, so that no one gets lenient screening while asking for strict.

Two things are missing:

- **The other commands.** `exec --privileged` (for docker and for compose) and `docker cp` into a container can reach the host, and both refuse `--strict-screen` today. Each of them needs its own decision, or strict mode promises more than it does.
- **A config setting.** A script does not pass `--strict-screen` itself. To protect the user against an untrusted script, strict screening would have to be a setting in the config file (`strict_screen = true`), with the option only for one-off use.

Why it is not done yet: the threat model trusts the command line, because whoever controls it can call docker directly. Strict screening only adds protection where the command line comes from somewhere less trusted than the user (a README, a project's Makefile or scripts, an agent), and where dockscreen is installed as `docker`, so that those commands reach it. So far, no one has needed it beyond the commands that support it.

## Image sections pinned by digest

An image section could name a digest as well as a repository. dockscreen would then refuse an image that matches the repository but not the digest, and would not run it with the section's settings. Whoever wrote the section trusted that content, and a different image under the same name is not that content. A section without a digest keeps matching any image that docker pulled from the repository.

A pinned section would also close a known gap for that image: with docker's containerd image store, a locally tagged or built image has a repo digest for its name, so today an image section applies to it as if docker had pulled it from the repository ([security review, 1a](docs/security-review.md)). A local image under the same name has a different digest, so a pinned section would not apply to it.

Why it is not done yet: an image's digest changes with every release, so the user would have to update a pinned section on each upgrade. That cost is worth paying for a few trusted images, but it needs a way to update the pin that does not invite pinning whatever is there.

## Image sections with and without a tag

Two sections could match one image: one for the repository (`mariadb`) and one for a tag of the repository (`mariadb:11`). dockscreen would apply the tagged section after the repository section. Settings for every version and settings for one version could then live side by side.

Why it is not done yet: the idea needs a rule for an image that docker pulled under several tags, and no one has needed version-specific settings yet.

## A doctor command

`dockscreen doctor` could report dockscreen's setup on this host:

- which docker dockscreen runs (`runtime._real_docker_path`), and whether the wrapper comes first on `PATH`;
- which config files dockscreen read, and which it refused as untrusted;
- whether the daemon counts as remote (`docker.is_remote`);
- which mount dirs contain sensitive paths (`inspect.sensitive_mount_dirs`, `Policy.check_mount_dirs`).

Why it is not done yet: no one has needed it. Each of these facts already shows up, as a refusal or a warning, when it matters for a command.
