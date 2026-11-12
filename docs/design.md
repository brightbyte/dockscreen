# dockscreen design

Audience: people who change dockscreen or review its security. Users want the README.

## Purpose

`docker compose up` on a project you just cloned gives that project the docker daemon's access: in effect root on the host. The same goes for `docker run` on an image you just pulled. dockscreen is a wrapper for `docker`, and can be installed as `docker`. It refuses a project or image that would reach outside its own directory or run with privileges, and adds hardening defaults to the rest. Everything it does not need to look at is passed to the real docker unchanged.

## Threat model

| Party | Trusted | Reason |
|---|---|---|
| Compose project: compose files, `.env`, env files, `include` and `extends` fragments, build contexts | no | it is the code you just cloned |
| Images, including their `/etc/passwd` and `/etc/group` | no | anyone can publish one |
| Your command line | yes | anyone who controls it can call `docker` directly |
| Your shell environment | yes | same reason; it does not configure dockscreen, though |
| The config files, `/etc/dockscreen/config.toml` and `~/.config/dockscreen/config.toml` | yes, if only you or root can write them | they are the only place that widens the policy |
| The docker daemon and the real `docker` binary | yes | they are the protected system |

Who a container runs as is the core of the policy; see [Users and groups](#users-and-groups).

Out of scope:

- Network exposure (`ports`, `extra_hosts`, `dns`).
- Anything chosen on the command line (`run -v`, `exec --privileged`).
- `${VAR}` interpolation copying values from your shell into a container.
- Clients that talk to the docker socket directly: scripts, IDEs, other tools. dockscreen is a wrapper, not a daemon plugin.

## Approach

1. Let docker parse its own input. dockscreen never parses compose files or mirrors `docker run`'s option handling to decide safety. It takes the real tool's own reading (`docker compose config`, `docker create` then `docker inspect`) and checks the result.
2. Check exactly the thing that runs. For compose, the checked config is written to a file and handed to compose as its only input. For `docker run`, the created container is checked before it is started.
3. Allowlist, fail closed. A compose key that is not listed is refused, so a new Compose feature stays denied until someone reviews it. Any error while inspecting counts as a refusal.
4. Decide users by ids, never by names. Docker resolves names in the image's own `/etc/passwd`, which the image controls; dockscreen resolves names on the host and hands docker numbers.
5. Fix the problems that have a safe fix, refuse the rest. Missing hardening is added, an image that would run as root is run as the default user, and everything else is refused with a message that names the way forward.
6. The config file is trusted completely, so the file is only read when nobody but its owner or root can have written it.

## Users and groups

Who a container runs as is the decision dockscreen spends most of its effort on. Root is rare and strictly opt-in. Running as the caller ("me") is common and easy, but never automatic. Every substitution is visible.

### Sources of ids

| Source | Trusted | Checked |
|---|---|---|
| Command line: `--user`/`-u`, `--as`, `--as-me`, `--allow-me` | yes | form only (see [Forms](#forms)) |
| Config file: `user`, `default_user`, `default_home`, `nobody_range`, at the top level and in image and project sections | yes | the file's ownership and permissions (see [Configuration](#configuration-and-options-config)) |
| Compose file: `user:`, hook `user:`, including values from `.env` | no | all rules |
| Image: its `USER`, `/etc/passwd` and `/etc/group` | no | all rules |

### Terms

- **me**: the caller's real uid and gid.
- **nobody range**: ids any project or image may use, mounts or not. `nobody_range`, 65530–65534 by default.
- **default user**: the replacement for an image's root user. `default_user`, 65534:65534 by default. It also gets `HOME` set to `default_home`, `/tmp` by default (not when it is root, nor when `default_home` is `""`), because the image's own `HOME` is root's. A `HOME` that the command line, an env file or the service sets stays: for `docker run`, a `HOME` in the created container that differs from the image's `ENV` counts as set by the caller. The image's own user and a configured user keep the home docker finds in passwd.
- **configured user**: a `uid:gid` that `user` sets in the config file, at the top level or in the image's or project's section.
- **allowed ids**: the nobody range, the default user, the uid and the gid of the configured user that applies to the service, and me when `--allow-me` was given (compose only). Each id is allowed on its own: with a configured `900:900`, `900:65534` passes too. A top-level `user` makes its ids allowed for every service of every project.
- **host mounts**: bind mounts, devices, `volumes_from`, secrets and configs, and a named volume whose `driver_opts` mount a device or a host path (`mounts.service_reaches_host`, `mounts.container_reaches_host`). Other named volumes and tmpfs are not.

### Forms

| Form | `--user`, `-u` | `--as` | `user:`, hook `user:` | Meaning |
|---|---|---|---|---|
| `uid:gid` | yes | no | yes | as given |
| `uid` alone | no | no | no | refused: docker would take the group and supplementary groups from the image; deriving them here would change the value's meaning |
| `name` | no | yes | yes | an account on this host, with its primary group |
| `name:group` | no | no | yes | account and group on this host |
| `${UID}:${GID}` and other variables | | | yes | interpolated by compose first, then read as the resulting form |

`--user` and `-u` take numbers only, so that a value dockscreen accepts means the same to docker. Docker resolves a name in the image, or for `exec` in the running container's `/etc/passwd`, which the container may have rewritten; resolving it on this host instead would quietly give `--user` a meaning docker does not have. A name is refused with a pointer to `--as`.

Names in `--as` and `user:` are resolved on this host, through NSS. A name unknown here is refused, even if the image defines it (`user: node`, `user: postgres`). Docker never sees a name: every user that runs is pinned as numeric `uid:gid`, and with a numeric group docker adds no supplementary groups from the image.

### Ids the project and the image may not choose

These apply to the uid, the gid and every supplementary gid, from `user:`, hooks and the image. Allowed ids are exempt.

| Id | Reason |
|---|---|
| 0 | root is never the project's or the image's choice |
| a user or group on this host (NSS) | the container would share that account's kernel limits (processes, inotify watches), and own its files in anything it mounts |
| in `/etc/subuid` or `/etc/subgid`, any owner | files with these ids belong to rootless containers on this host |
| 65535 or 4294967295 | `(uid_t)-1`: many tools read it as "no id" |
| anything else, with host mounts | the id decides which host files the container can write, so it must be an allowed id |

### Deciding the user

Compose services:

1. **The service sets `user:`.** It is resolved (see [Forms](#forms)) and checked. If the rules refuse it, the run is refused: the project asked for this id, so there is no fallback.
2. **No `user:`, and a configured image user applies** (see below): that user, root included, without a notice.
3. **No `user:` otherwise:** the image's own user.
   - root in any position (uid, gid or a supplementary gid): the default user, with a notice;
   - anything else: checked with the service's mounts, and the run is refused if the rules refuse it.

Hook users follow step 1. Services that will not start get the default user, so a mistake about which services start fails safe.

`docker run`, and `docker compose run` for the service it names: a user from the command line is used as given. Otherwise, steps 2 and 3 apply.

`docker start` and `restart`: an existing container cannot be rewritten, so one whose user steps 2 and 3 would replace or refuse is refused. Docker does not record where a container was created, and its labels, which its image can set, prove nothing, so it is judged without a directory: no project section of the config file applies, and under `--strict-screen` only the configured `mount_dirs` allow its bind mounts. Compose `start` and `restart` take no user and are not checked: they start containers that `up` or `create` made.

`exec` (`docker exec`, `compose exec`): a user from the command line is used as given. Without one, the process runs as the container's own user, which was checked when the container started, if dockscreen started it.

### Image and project sections

An image section (`[images."REPOSITORY"]`) names a repository: it trusts the image's maintainer, not one image. It applies when all of these hold:

- The repository is the same after normalisation: registry and namespace are filled in, so `mariadb` means `docker.io/library/mariadb` and does not match `evil.example/mariadb` or `someone/mariadb`. The tag plays no part.
- The image was pulled from that repository: its `RepoDigests` contain an entry for it. A project, or an earlier run, can build or tag a local image under any name, and such an image has no repo digest for the repository.
- The service has no `build:`.

`audit` gives the reason when a section for the repository exists but did not apply.

The policy checks run before the images are pulled, so they apply the section the image name points to (`config.name_matches`). Once the images are there, `serviceinfo._find_section_images` records where each image was pulled from (`project.ServiceImages`), the policy for the project takes the section each image proves from that (`Screener.project_policy`, `Screener.section_for`), and the check of the config that will run (with `Decisions.policy`) applies only those: a service that passed on the name alone is refused if its image does not prove it.

A project section (`[projects."DIRECTORY"]`) applies to the compose project directory, or for `docker run` and `audit` the current directory, when it is that directory or below it, compared after resolving symlinks.

`config.effective` applies the top level, the image section, then the project sections, outermost first: a single value replaces, a list is added to. Both come from the scope a command is screened in (`scope.Screener`: the caller, this host and `--allow-me`) and from where the target is: a project's directory, or the current one for a container a command line runs. `Screener.policy(directory, section)` is the one way to a policy with those settings; `Screener.project_policy(project)` gives one per service besides (`Policy.per_service`).

### Command-line options

| Option | Where | Effect |
|---|---|---|
| `--user uid:gid`, `-u uid:gid` | `docker run`, `create`, `exec`, `audit`; compose `run`, `exec` | that user, as given |
| `--as NAME` | the same | `--user=uid:gid` of that account on this host |
| `--as-me` | the same | `--user=` my `uid:gid` |
| `--allow-me` | before the compose subcommand only; docker's commands refuse it, and `audit`, `create` and `run` take `--as-me`, `--as` or `--user` | me becomes an allowed id: in `user:` (literal, name or `${UID}`), and as an image's own user |

`--as`, `--as-me` and `--allow-me` are dockscreen's own: docker and compose never see them. The user options go after the subcommand and before the image, service or container.

`--as-me` before a compose subcommand is refused with a pointer to `--allow-me`: choosing one user for every service of `up` at once makes no sense. A project says which services run as the caller with `user: "${UID}:${GID}"`; dockscreen passes `UID` and `GID` to compose as the real ids, overriding any already set, and the rules refuse them unless `--allow-me` was given.

### Notices

Every change dockscreen makes to the things it runs is announced, as a notice (`notice.Notice`), whose severity sets the mark of its line: cyan for info, yellow for a warning (check this). A reason to stop a command is a finding (`finding.Finding`), marked red, whose kind is refused or failed. The mark is a coloured `●`, so without colour (a pipe, `NO_COLOR`) the two look alike and the words alone must name the outcome. For compose, each change to a service's key is a `projectpatch.Substitution`, whether hardening (`hardening.changes`, with names resolved by `Policy.resolve_user_names`) or the users and pins of the images (`Policy.user_changes`, kept in `decisions.Decisions.changes`) made it, and the definition that runs is the resolved one with all of them made, in that order: the patches are joined and applied in one step (`projectpatch.ProjectPatch`, `projectscreening.finish`); info ones of the same kind share one line that names their services (`projectpatch.SubstitutionGroup`).

A message has two parts: the facts, and an optional help part that suggests a next step. The help part is shown after ` - ` only in helpful mode: with `--helpful` or `--verbose` before the subcommand, or for the `audit` commands. `--verbose` is dockscreen's own there, because passing it on would make docker and compose noisy. Refusal reasons carry their help the same way (`finding.Finding`, and `notice.Notice` for messages that stop nothing, which also name their subject), though a reason built inside the policy checks (SELinux label, `--allow-me` for your own id) still has its hint in the text.

- **routine** (cyan): a default added where nothing was set (`cap_drop`, `security_opt`, `--cap-drop`, `--security-opt`), a name resolved to ids, a checked image user passed on as numbers, an image pinned by id with `pull_policy: never`. These rarely change the thing's behaviour. The defaults can still break a program that needs a capability or a setuid binary, and the line says so.
- **check this** (yellow): a change that can alter behaviour: an image's root user replaced by the default user, a service that is not started getting the default user regardless of its image's choice, a `cap_drop` or `security_opt` the project set itself that dockscreen extends.

- The default user replaced an image's root user: one line per service, on every run.
- The configured default user is root: one line on every run.
- A configured image user, root included: a routine line per run, `audit` lists it too.
- A name resolved on this host (`--as`, `user:`): one line naming the ids.

## Mechanisms

The code is in layers, one package each, and each imports only its own and the ones before it (`tests/test_layering.py` checks this). The docstring of each package (its `__init__.py`) lists its modules by purpose, the work it leaves to other packages, the constraints on its modules, and the exceptions to them.

In this context, the term "screening" is used to refer to the process of checking one target (a compose project, a container, a bake definition) before it is handed to docker. It involves gathering the target's facts through docker and having the policy judge them. Each `*screening` module in `screen` screens one kind of target, and a command has its targets screened before it runs anything.

Layer overview:

1. `util`: the shared vocabulary: ids, command lines and dockscreen's own options in them, and `messages`, the one place that writes to the terminal.
2. `model`: the targets the policy judges (projects, containers, images, builds), the host paths their mounts reach, and the origins of their values (`origin`), built from data given to them, without reaching the host or docker. Knowledge about the thing being checked (its location, its daemon, the origins of its values, its reach into host files) belongs to it, not to the policy.
3. `host`: this host, the caller and the config file, and the one way to reach docker. A failure is raised (`DockerError`), not judged.
4. `policy`: the rules, grouped by subject in `rules`, behind one facade (`Policy`); the decisions and verdicts they give; the changes it works out for a target, held as patches (`hardening`, `projectpatch`, `commandlinepatch`); and the fixes `harden` writes out (`projectfixes`). It never calls docker.
5. `screen`: gathers docker's view of a target and the command line's, and has the policy judge it, in the stages each kind of target needs (`projectscreening`, `containerscreening`, `bakescreening`, `userscreening`). It returns its findings, for the command to print.
6. `commands`: one module per command dockscreen gates, named after it, which has the targets screened, prints the findings, and hands over to docker or stops; the dispatchers that choose among them (`docker` for `docker`, `docker_compose` also for `docker compose`); `projectrun`, which compose `up`, `create` and `run` share; and `helptext`.
7. The entry point, at the top of the package: `docker_cli`, which reads the command line, loads the runtime and hands both to `DockerCommand`.

A command line is read one level at a time (`commandline.CommandLine`): the options before the command (`lead_args`), the command (`cmd`) and the arguments after it (`args`), with dockscreen's own options before the command taken out (`own_args`). `main_commandline` reads docker's level; `CommandLine.subcommand` reads the level of a command that has commands of its own, such as `compose -f a.yml up` or `buildx --builder b bake`, keeps the dockscreen options given before it, and records the docker command line before it (`prefix`), so that the whole of it can be handed on (`full_argv`).

The `docker` and `docker compose` dispatchers are built alike. A command object (`commands.docker.DockerCommand`, `commands.docker_compose.ComposeCommand`) holds a command line and the runtime, gives help (`_help_request`, `show_help`) before anything else, `--strict-screen` included, and hands the command to its module in `commands`; everything it does not screen is handed to the real docker (`_passthrough`). `docker container run` and the other gated commands after `container` are read as their short form (`commands.docker._short_form`). A command's module has a `gate(cli, runtime)` that takes the command line with the command as its `cmd`, checks, and then runs the checked target, never reading its input a second time; where the check stands on its own it is a `check` that returns the checked target and the reasons it may not run, and where dockscreen has an audit of the command, an `audit` that checks and reports. Its `help(name)` returns the help of each command it implements (`helptext.HelpTopic`), which the dispatcher lists in its `HELP`; dockscreen's own compose commands take theirs from their function's docstring, up to its `Parameters:` list (`helptext.command_topic`). A command that does not support `--strict-screen` refuses it itself; the dispatcher refuses it for everything it does not screen. The arguments of `run`, `create` and `exec` are read by `runargs` and `userargs`. The commands use `docker.is_remote` to refuse a daemon that is not this host's, and `userscreening.screened` to have the policy judge and resolve the users the command line gives, in one step.

### Compose (`commands.docker_compose`, `ComposeCommand`, `commands.compose_*`, `inspect`, `hardening`, `policy`, `serviceinfo`, `imageusers`, `projectscreening`)

For `up`, `create`, `run`, `watch`, `scale` and `alpha`, the project (`project.Project`) is screened in stages, each only once the one before it passed (`projectscreening`). Each stage is a function from the previous stage's result to the next stage's input, or to the report that stops screening, and judges its findings with a check of its own: `load_project` gives a `LoadedProject`, `check` clears it (`ClearedProject`), `decide` takes only a cleared project, and `finish` makes the runnable project (`RunnableProject`). The types say which stage may follow which: nothing is pulled or built for a project that was not cleared, and nothing runs that was not checked last.

1. `inspect.project` runs `docker compose config --format json --no-env-resolution --profile '*'`. All profiles are included so that a service named on the command line is checked too. Without env resolution, `env_file` paths stay visible to the policy instead of being inlined. The project directory is worked out the way compose does it (`inspect.locate`), and the policy judges it before the config is read (`Policy.check_location`). A `.env` that sets `COMPOSE_FILE` is refused, because it could send compose to a different directory than the one checked.
2. `hardening.changes` adds `cap_drop: [ALL]` and `no-new-privileges:true` where they are missing, and has the policy resolve names in `user:` and hook users to ids on this host (`Policy.resolve_user_names`, with `hostusers.HostAccounts`); a name unknown here stays a name, which the policy refuses.
3. `Policy.check_project` applies the allowlist (below), and the id rules (`Policy.id_problems`) to every id the project gives, and `Policy.check_daemon` refuses a daemon that may not be this host's. Services that set no `user:` are exempt for now: their user comes from the image (`origin.Origin.IMAGE`), which decides it.
   Once that passes, the project's name is checked too (`inspect.name_conflicts`: `Policy.check_project_name`, with the directories `inspect.made_from` asks docker for; a failure to ask is a failure, not a refusal). It is the project's choice (`name:`, or `COMPOSE_PROJECT_NAME` in its `.env`) and decides which volumes, networks and containers compose uses, replaces and removes, so a name that other projects' containers already have is refused. Containers of that project name, running or not, say where they were made from in their `com.docker.compose.project.working_dir` label; one made from another directory, or without the label, is a conflict. `-p` and `COMPOSE_PROJECT_NAME` in the environment are the person's choice and are not checked. `down`, `rm`, `stop`, `kill`, `restart`, `start`, `pause` and `unpause` get only this check, before compose runs.
4. `serviceinfo.prepare`, with `imageusers` for the images:
   - asks compose which services will start (`config --services`);
   - pulls or builds their images by the project's own `pull_policy`, so automatic updates keep working;
   - for each one without `user:`, creates a container with `--pull=never` and looks at its image as far as the policy needs (`Screener.look`, which gives `project.ServiceImages`); the policy decides from that once, as `docker run` does (below), and that decision is the project's `Decisions` (`Screener.decide`);
   - skips the service that `run -u uid:gid` names: the command line chose its user.
5. `projectscreening.finish`, which makes the substitutions of `decisions.Decisions.changes` (`Policy.user_changes`):
   - every decided user is pinned as numeric `user: "uid:gid"`, so the runtime resolves nothing in the image;
   - services that fall back, and services that will not start, get the default user, so a mistake about which services start fails safe;
   - services whose image was looked at get `pull_policy: never` and, unless built, `image:` set to the checked image id, so neither a pull nor a moved tag changes the image that runs;
   - the policy runs again on the result, with each value it set judged by where it came from (`project.Project.origins`, from the substitutions that set them): an image's own user was checked when it was decided, a user from the config file (configured, or the default user it sets) is trusted, so the rules' objections to it are pointed out, not refused, and dockscreen's own choices (its own default user, the defaults, the pinned image) is checked like the project's.
6. Before anything is pulled or built (`projectscreening.decide`, ahead of step 4), compose is asked for the config of the generated file, and the run is refused unless it equals the config that was checked: compose interpolates the files it reads.
7. `projectrun.check_and_run` writes the final config to a mode 0600 file in a private temporary directory. It runs `docker compose -f FILE --project-directory DIR --project-name NAME SUBCOMMAND …` as a child process, then removes the file.

`build` and `bake` get only `Policy.check_project_build` (`projectscreening.check_build`, `bakescreening.check`), with no runtime checks. A service's `build:` is a `imagebuild.ImageBuild`, as a bake target is, and the rules they share are `Policy.check_build`. Each build knows the directory its paths are relative to (its project's, or the one bake ran in), and its inputs are judged against that:

- build contexts, Dockerfiles and secret files must be inside the project;
- no `ssh`, no host network, no `privileged`;
- no `x-` keys in `build`, because `buildx bake` reads `x-bake` and can write to the host.

`audit` (`compose_audit`) runs the same stages and reports, ending with a verdict (`report.Report.verdict`): passed, refused (the policy says no) or failed (the config could not be read, `docker.DockerError`, or an image could not be pulled, built or looked at, `decisions.Decisions.report`). `harden` (`compose_harden`) prints a compose override that fixes the problems with a mechanical fix and lists the rest as comments. The fixes are the policy's (`projectfixes`): unlike `hardening`, which is applied to every run and leaves the project alone, they change the project's definition, for the person to adopt. The patched project goes through the same stages, name check included, before its images are looked at, and a service whose image chose a user that is not acceptable gets one set (`projectfixes.set_image_users`).

### Origins and trust (`origin`, `findings`)

Findings come only from `policy`: the policy and the image decision judge, and a failure to look is turned into a finding there (`finding.failure_of`). The host layer only raises errors, with docker's output (`DockerError.output`). Every rule is a method of `policy.Policy`, which holds the settings the rules apply with, whether a rule reads them or not. The rules for the users the command line gives (`Policy.check_user_options`), the daemon (`Policy.check_daemon`) and the project name are policy rules like the others; the command line's reading (`userargs.GivenUsers`) only records the users given, for the command to have the policy judge and resolve them.

Every value the policy judges has an origin (`Origin`): the command line, the config file, the project, the image, or dockscreen itself. A policy finding in a value from a trusted origin (`origin.TRUSTED`: the command line and the config file) is a warning notice, not a refusal (`finding.judged`); `--strict-screen` drops the command line from the trusted origins. The origins are as coarse as docker's view: everything in `compose config` comes from the project, and everything in a container that `docker run` created comes from the command line, except a user equal to its image's. A key dockscreen sets takes the origin its substitution names (`projectpatch.Substitution.origin`): the config file for a configured user or a default user it sets, the image for the image's own user pinned as numbers, dockscreen for its own default user and the defaults and pins it chose. `docker run`, which re-creates the container with the decided user, gives that user the same origin. A substitution that only adds to the project's list or respells its value (a user name resolved to ids) names none, and the key stays the project's.

### The policy (`policy`, `rules`)

Every structure has its own key list, in the rules that judge it (`servicerules`, `projectrules`, `buildrules`): service, mount, build, volume, network, secret, deploy, develop, hooks and top level. A key is either harmless, so any value passes, or has a check function in `servicerules.SERVICE_CHECKS`.

| Area | Rule |
|---|---|
| `user`, hook `user` | `uid:gid` after names are resolved (a uid alone is refused); each id passes the id rules below, with the service's mounts |
| privileges | `privileged`, `cap_add`, `devices`, `gpus`, `cgroup_parent`, device reservations: refused; `group_add`: refused, because older daemons resolve a number as a group name from the image first; `cap_drop` must include `ALL`; `security_opt` must be exactly no-new-privileges; `runtime` only `runc` |
| namespaces | `pid`, `ipc`, `uts`, `userns_mode`, `cgroup`, `network_mode`: no `host`, no `container:` |
| mounts | bind sources, after `realpath`, inside the project or the configured `mount_dirs`; types `volume`, `tmpfs` and `image` allowed |
| files read on the host | `env_file`, `label_file`, secret and config `file`, build contexts, `develop.watch` paths: inside the project |
| volumes and networks | named `<project>_<key>`, not `external`; volumes use the local driver, and `driver_opts` may not turn one into a bind or network mount; networks use `bridge` or `none` |
| `develop.watch` | no `sync+exec`, which runs a command in the container |
| `x-` keys | ignored, as compose does, except in `build` |
| service names | no leading `-`, because names go to compose as arguments; `pull` and `build` of the images get `--` before them |

### Users (`rules.userrules`, `hostusers`, `image`, `imageuser`)

`Policy.id_problems` (`rules.userrules`) implements [the id rules](#ids-the-project-and-the-image-may-not-choose), with their facts in `userrules.IdFacts`. It reads `/etc/subuid` and `/etc/subgid` when it checks, and looks up local accounts through NSS, so LDAP and sssd accounts count.

`Screener.assess` implements [steps 2 and 3](#deciding-the-user) for compose and `docker run` alike, in two parts: `Screener.look` reads the image as far as the policy needs (`image.Inspected`: where it was pulled from, its own user, the container's user, and its passwd and group files only if the decision needs them, `Policy.needs_user_files`), and `Policy.check_image` (`rules.userrules`) decides from those facts alone; `verdict` states the decision. `config.section_for` decides which image section applies, and `config.effective` whether a `user` is configured. Otherwise the image's identity is resolved from its `/etc/passwd` and `/etc/group`, the way moby does it, which are copied out of a container that is created but never started (`docker cp`, capped at 1 MiB). Because the result is pinned as numbers, docker reads neither file at run time, so a difference between this reading and docker's can at worst refuse a good image. The `UserDecision` says where the user comes from, as an `Origin` like any other value's (the command line, the config file, the image, or dockscreen for its own default user; none for an image that could not be looked at), and whether it is the default user instead of the image's root (`replaces_root`), the image (`image.Image`: the name, and the id that is pinned), and the findings: refusals, failures to look, and a notable finding for an image section that does not apply.

### The `docker` wrapper (`docker_cli`, `commands.docker`, `runargs`, `commands`, `hostusers`)

- `run` becomes `create`, `inspect`, check, `start`:
  - The daemon parses the command line. `runargs` reads only far enough to find the image and the `run`-only flags.
  - `containerscreening.create` refuses if that reading disagrees with the daemon's container (`_verify_split`).
  - Anything accepted removes the container and creates it again with `--user=uid:gid` as numbers: the default user, the configured image user, or the image's own ids.
- `create` (`docker_create`) gets the defaults and user resolution. Its container is checked when it is started.
- `start` and `restart` (`docker_start`, `containerscreening.check_existing`) check existing containers. These can't be rewritten, so a container whose user would be replaced (default or configured user) is refused.
- `exec` (`docker_exec`) checks only the form of the user (see [Forms](#forms)).
- `buildx bake` runs `docker buildx bake --print` with the same command line, docker's and buildx's options included, which builds nothing and gives the definition with the command line applied, and the policy judges it (`Policy.check_bake`, each target a `imagebuild.ImageBuild`, with the rules `Policy.check_build` shares with compose's builds): build sources and secret files inside the current directory, no host network, `entitlements` or SSH agent, no `output` or `cache-to` that writes files, no secret copied from a variable, no target key it does not know. `--print` and `--help` pass through. `buildx build` and `docker build` are not screened: their Dockerfile cannot reach the host without options, and the command line is trusted.
- `audit` (`docker_run.audit`) takes a `run` command line, creates the container as `run` would (pulling if `run` would), reports `run`'s outcome and removes it. An image that could not be looked at gets a decision whose findings are failures (`UserDecision.failure`): `run` refuses it like a refusal, the audit reports it as failed. `Policy.check_container` judges the inspected container as a service (`container.Container.definition`, read back into compose service keys) with `Policy.check_service`, with the current directory as the project: a command-line request that a project could not make is reported, and refused with `--strict-screen`.
- Every `create` gets `--cap-drop=ALL --security-opt=no-new-privileges:true` placed before the user's arguments, so the command line can override them.
- Users chosen on the command line: see [Command-line options](#command-line-options).
- A daemon that is not the local default is refused (`-H`, `--context`, a non-unix `DOCKER_HOST`, a non-default context): host ids and paths mean nothing there.
- `compose` goes to `docker_compose` (see [Compose](#compose-commandsdocker_compose-composecommand-commandscompose_-inspect-hardening-policy-serviceinfo-imageusers-projectscreening)). Everything else is exec'd to the real docker unchanged. The real docker is the configured `docker`, or else the next `docker` on `PATH` that is not the wrapper. Empty and relative `PATH` entries are skipped, so the current directory cannot supply it, and dockscreen warns about them. Without a real docker, dockscreen stops with an error.

### Configuration and options (`config`)

The config files are TOML, read with `tomllib`. The user's file overrides `/etc` key by key, and sections by name. Unknown keys are an error. A missing user file is created from `config.template.toml`, mode 0600 in a 0700 directory, with every setting commented out: active defaults there would override `/etc`.

| Key | Default | Effect |
|---|---|---|
| `default_user` | `65534:65534` | replaces an image's root user; a notice on every run if it is root |
| `default_home` | `/tmp` | `HOME` of the default user, which has none of its own; `""` leaves `HOME` alone |
| `nobody_range` | `[65530, 65534]` | ids any project or image may use, mounts or not; may not include 65535 |
| `mount_dirs` | none | absolute directories, besides the project, that bind mounts may come from |
| `user` | none | the user every image runs as when the service or command line chooses none |
| `security_opts` | none | security options allowed besides no-new-privileges |
| `docker` | the next `docker` on `PATH` | absolute path of the real docker; top level only |
| `[images."REPOSITORY"]` | none | the settings above, for images pulled from the repository (no tag) |
| `[projects."DIRECTORY"]` | none | the settings above, for a project directory and below |

Strict modes, as ssh does it: the file and every directory above it must be owned by the caller or root and not writable by group or others, or dockscreen refuses to run. Strict modes cannot stop an agent that runs as the caller; only a root-owned file in `/etc` does. They do not cover the `docker` binary the file names either.

Mount dirs and the project directory are checked against sensitive paths (system directories, `$HOME`, the config files, the docker socket), after resolving symlinks: a mount dir that contains one gets a warning on every run, a project directory that contains one is refused. The upward search for a compose file stops at `$HOME` and at the first directory that the caller does not own.

| Option, before the subcommand | Effect |
|---|---|
| `--allow-me` | the caller's own ids become allowed ids, for this run; compose only |
| `--strict-screen` | the command line is untrusted too (`origin.STRICT`): `audit`, `run`, `start` and `restart` refuse its requests that a project could not make (`Policy.check_container`), and so does `compose run`, which judges the service as its options change it (`runoptions`, substitutions with the command line as their origin); `create` and `buildx bake` accept it, since create's container is judged when it starts and bake judges its whole definition anyway; refused before any other subcommand until it is supported there; help is given either way |
| `--skip-screening` | no checks, no defaults, and a warning on every use |

Text from the project or the image is escaped (`messages.printable`) before it is printed or written into a `harden` patch, so it cannot forge output lines or send terminal control sequences.

## Direction: one step from rule to change

This section is for developers changing dockscreen's modifications to the things it runs.

Every change dockscreen makes comes from a rule, and is applied in one step: a rule judges and states the changes, as findings, notices and changes; the command applies the changes to the thing it runs and reports them from the same objects. Reading the command line changes nothing.

- For compose, the thing to run is the project's definition, and the changes are a `projectpatch.ProjectPatch`, whose `Substitution`s each set a key of a service. `hardening` and the user rules (`Policy.resolve_user_names`, `Policy.user_changes`) give patches, `projectscreening.finish` joins them and applies the result (`ProjectPatch.applied_to`), and the patch reports itself (`notices`).
- For `docker run` and `create`, the thing to run is the arguments (`runargs.RunArgs.create_args`), and the changes are an `commandlinepatch.CommandLinePatch`, whose `Amendment`s each put arguments before the user's own, so that the user's later options override them. `hardening.container_defaults` and the user rules (`Policy.user_amendments`) give patches, and `CommandLinePatch.applied_to` applies them. The two kinds apply differently, hence two types; both carry the notice that reports them.
- `--as` and `--as-me` stay in the arguments as their `UserOption`, as they were read. The rules judge them (`Policy.check_user_options`) and resolve them (`Policy.resolve_user_options`), and `resolved` replaces them in place, all in one call for the commands (`userscreening.screened`), since their order against `--user` decides which one docker uses. An argument list that still has one cannot be resolved, so it cannot reach docker. The account is looked up while reading, as `Screener.look` reads an image: that is looking, not changing.

The user rules are one module (`rules.userrules`): which user a service, an image or a command line may have, and the changes that follow, for compose and for `docker run` alike. `UserDecision` is the result of deciding, which the rules turn into the changes of each kind of thing to run (`Policy.user_changes`, `Policy.user_amendments`).

The point is less to keep in mind: one way from a rule to the running thing. A change in this direction that adds more code or concepts than it takes away is to be reconsidered, not finished.

## Tradeoffs and decisions

| Decision | Alternative rejected | Cost accepted |
|---|---|---|
| Allowlist of keys | denylist of known-bad keys | false refusals until a new key is reviewed and listed |
| Run compose from the generated config | re-run compose on the project's own files | compose runs as a child, not via `exec`, and shows a temporary file as its config |
| Ask docker (`config`, `create` + `inspect`) | parse compose files and run options ourselves | an extra daemon round trip per image; depends on compose's output format |
| The default user (nobody) for root images | refuse | images that start as root and drop privileges (postgres, redis) fail on their data directories until a user is configured or chosen |
| With mounts, only allowed ids | accept any non-root image user | more images are refused; a `user` in the image's section and `--user` are the way out |
| Names resolved on the host, never in the image | let docker resolve them | `user: postgres` means the host's postgres, or is refused, unlike plain compose |
| A uid without a group is refused | derive the gid | a silent change in behaviour would be confusing |
| Image sections by repository, checked by repo digest | by name only; by digest | trusts the maintainer, not one image; locally built images get no image section |
| One config file, trusted completely | environment variables | the file needs strict ownership; an agent running as the caller can still edit it |
| `pull_policy: never` only in the generated file | pin in the project or in `harden` output | none; pinning in the project would silently stop its updates |
| Pull and build before deciding | decide only on images already present | `up`, `audit` and `harden` can pull and build, but only after the static checks pass |
| Wrapper on `PATH` | daemon authorization plugin | anything that talks to the socket directly is not covered |
| Remote daemons refused | check anyway | dockscreen does not work with remote contexts |

## Known gaps

- The project name check looks at containers only: volumes and networks carry no directory label. A project whose containers are all removed but whose volumes remain can have its name taken over. A `-p` given by the person is never checked.
- `start` and `restart` trust a container whose user differs from its image's, as `run --user` is trusted: dockscreen cannot tell one made on a command line from one a project's script made. They do not examine `HostConfig` (privileged, binds, devices). A user that is the image's own is resolved by the daemon at start, from the container's files, so the safety rests on `imageuser` reading ids as the daemon does. `restart` has a window in which a running container with a writable `/etc/passwd` can change the result after the check.
- `bake` resolves relative paths in its definition against the current directory, not against the directory of a bake file given with `-f`; a bake file elsewhere is checked against the wrong base. Other plugin commands that start containers (`docker sandbox run`, `docker model run`) and swarm `service create` and `stack deploy` are passed through.
- Compose `start` and `restart` are passed through unchecked. A container that plain `docker compose create` made, without dockscreen, can be started through them.
- Image sections cannot apply to a locally built image; pinning by digest is a [future idea](../FUTURE.md).
- `harden` writes `user: "${UID}:${GID}"` where an image's user is refused, which needs `--allow-me` to run.

## Maintaining

- A legitimate key is refused: check that it can't reach the host, then add it to the matching list in `policy/rules`, or give it a check function. Never switch to refusing only known-bad keys.
- Compose adds a global option that takes a value: add it to `docker_compose.GLOBAL_OPTS_WITH_VALUE`, or the subcommand is misread. For `docker`, the list is `commands.docker.DOCKER_OPTS_WITH_VALUE`, and for `run`/`create` it is `runargs.LONG_VALUE_FLAGS`.
