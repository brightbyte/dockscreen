# Ideas for later

Not planned work: things worth doing once there is a need for them. Each says why it is not done yet.

## Strict screening for run and friends

`--strict-screen` makes `audit` treat the command line as untrusted. Then the audit fails for each request that a compose project or an image may not make: privileged, cap_add, devices, host namespaces, other security options, bind mounts outside the current directory, a user that the id rules refuse. The same check could refuse those things at execution time, for `run` first. `containerscreening.command_line_findings` already computes them from the created container, so `docker_run.gate` would only need to remove the container and refuse.

It is not done yet, for three reasons:

- The threat model trusts the command line, because whoever controls it can call docker directly. Strict execution only adds protection when the command line comes from somewhere less trusted than the user running it (a README, a project's Makefile or scripts, an agent) and dockscreen is installed as `docker`, so that those commands reach it.
- A script will not pass `--strict-screen` itself. To protect against untrusted scripts it would have to be a config setting (`strict_screen = true` in the config file), with the flag only for one-off use.
- Strict `run` alone leaves gaps: `create`, `start` of a container created elsewhere, `exec --privileged`, `compose run -v` and `--cap-add`, `docker cp`. Each needs its own decision, or strict mode promises more than it does.

Until then, dockscreen refuses `--strict-screen` for every subcommand except `audit`, so that no one gets lenient screening while asking for strict.

## Image sections pinned by digest

An image section could name a digest as well as a repository. dockscreen would then refuse an image that matches the repository but not the digest, and would not run it without the section's settings: whoever wrote the section trusted that content, and a different image under the same name is not that content. A section without a digest keeps matching any image pulled from the repository.

## Image sections with and without a tag

Two sections could match one image: one for the repository (`mariadb`) and one for a tag of it (`mariadb:11`), with the tagged section applied after the repository section. Then settings for every version and settings for one version can live side by side. The idea needs a rule for an image pulled under several tags.

## A doctor command

`dockscreen doctor` could report dockscreen's setup on this host. It would report which docker it runs (`runtime._real_docker_path`), and whether the wrapper comes first on PATH. It would list the config files it read, or refused as untrusted. It would say whether the daemon counts as remote (`docker.is_remote`), and which mount dirs contain sensitive paths (`inspect.sensitive_mount_dirs`, `Policy.check_mount_dirs`).

It is not done yet because no one has needed it. Each of these facts shows up already, as a refusal or a warning, when it matters for a command.
