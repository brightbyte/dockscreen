# User and group ids: draft spec

Audience: whoever implements or reviews how dockscreen decides the uid and gid a container runs as.

Goal: running as root is rare and strictly opt-in. Running as the calling user ("me") is common and easy, but never automatic. Every substitution is visible.

## Sources of ids, and how far they are trusted

| Source | Trusted | Checked |
|---|---|---|
| Command line: `--user`, `--as`, `--as-me` (`docker run` only), `--allow-me`; `run -u` and `exec -u` for compose | yes | form only (see [Forms](#forms)) |
| Config file | yes | ownership and permissions of the file (see [Config file](#config-file)) |
| Compose file: `user:`, hook `user:`, `group_add`, including values from `.env` | no | full rules |
| Image: its `USER` and its `/etc/passwd` and `/etc/group` | no | full rules |

Environment variables no longer configure dockscreen: `DCOMPOSE_UID`, `DCOMPOSE_GID`, `DCOMPOSE_DIRS` and `DCOMPOSE_DOCKER` are removed. Whatever the config file says is considered safe.

## Terms

- **me**: the real uid and gid of the caller.
- **nobody range**: ids that any image or project may use. Comes from the config file. Defaults to 65530–65534.
- **default user**: what a service or container runs as when nothing chose a user and the image's own user is root. Comes from the config file. Defaults to nobody (65534:65534).
- **image user**: a `uid:gid` from the config file for one image repository. It replaces the image's own user when nothing else chose a user.
- **allowed ids**: the nobody range, the default user, and the matching image user. Also me, when `--allow-me` was given, or `--as-me` on `docker run`.

## Forms

| Form | `--user`; `-u` for `run` and `exec` | `--as` | compose `user:`, hooks | Meaning |
|---|---|---|---|---|
| `uid:gid` | yes | no | yes | as given |
| `uid` alone | no | no | no | rejected. Docker would take the group and supplementary groups from the image; deriving the gid would silently change behaviour |
| `name` | no | yes | yes | an account on this host, with its primary group |
| `name:group` | no | no | yes | account and group on this host |
| `${UID}:${GID}` and other variables | n/a | n/a | yes | interpolated first, then treated as the resulting form |

`--user` and `-u` take numbers only. Docker would resolve a name in the image, which decides what the name maps to, and resolving it on this host instead would silently give `--user` a different meaning from docker's. For `exec`, docker resolves the name in the running container's `/etc/passwd`, which the container may have rewritten. A name is refused, with a pointer to `--as`.

Names in `--as` and `user:` are resolved on this host. A name that does not exist on this host is rejected, even if the image defines it (`user: node`, `user: postgres`). Docker never sees a name: whatever runs is pinned as numeric `uid:gid`. A numeric gid means docker adds no supplementary groups from the image.

## Ids that are never accepted from an untrusted source

They apply to the uid, the gid and the supplementary gids alike. They are rejected in `user:`, in hooks, in `group_add` and as the image's user, unless they are allowed ids:

- 0 (root);
- an id that exists on this host as a user or group;
- an id in a subordinate range in `/etc/subuid` or `/etc/subgid` (any owner). Files with these ids belong to rootless containers on this host;
- 65535 and 4294967295, which tools read as "no id".

### With host mounts

Host mounts here are bind mounts, devices, `volumes_from`, secrets and configs. With any of them, the id must also be an allowed id, because what the container can write on the host depends on it. Without mounts, any id not excluded above is accepted.

## Deciding the user

### Compose services

1. **The service sets `user:`.** Resolve it as described in Forms, then check it. If it isn't allowed, reject the run. There is no fallback: the project asked for this id explicitly.
2. **No `user:`, and the config file has an image user for its image:** the service runs as that user, root included.
3. **No `user:` otherwise:** the image's own user decides.
   - root → the default user;
   - otherwise, check it under the rules above, and reject the run if it is not accepted.

Hook `user:` follows step 1.

### `docker run`

- `--user`, `--as` or `--as-me` before the image: used as given, with no checks beyond the form.
- Otherwise, the same as compose steps 2 and 3.

`--allow-me` makes an image whose own user is me acceptable.

### `docker start` and `restart`

An existing container cannot be rewritten. A container whose user would be replaced or rejected under the rules above is rejected.

### `docker exec` and `compose exec`

`-u` takes numeric `uid:gid` only (see [Forms](#forms)), and is trusted. Without `-u`, the process runs as the container's own user. That user was checked at start if dockscreen created the container.

### Applying a user from the config file

A setting names a repository: it trusts the image's maintainer, not one specific image. An image matches when all of these hold:

- **The repository is the same after normalisation.** Registry and namespace are filled in: `mariadb` means `docker.io/library/mariadb`, and does not match `evil.example/mariadb` or `someone/mariadb`. The tag plays no part.
- **The image was pulled from that repository.** Its `RepoDigests` (`docker image inspect`) contain an entry for the repository. A project, or an earlier run, can build or tag a local image under any name; such an image has no repo digest for that repository, and does not match.
- **The service has no `build:`.**

Images built locally have no repository to check against, so a setting cannot match them. Trusting one exact image, by digest or image id, is deferred.

`audit` names the setting that matched. When a service's repository has a setting but the image does not match, `audit` says why.

## Command-line flags

| Flag | Effect |
|---|---|
| `--allow-me` | me becomes an allowed id: in `user:` (literal, name or `${UID}`), and as an image's own user |
| `--as-me` | `docker run` only: stands for `--user=` my `uid:gid`, and implies `--allow-me`. Compose refuses it with a message pointing to `--allow-me`: deciding for every service at once makes no sense, and the services that should run as me say so with `user: "${UID}:${GID}"` |

## Variables for compose files

dockscreen passes `UID` and `GID` to compose as the real ids, always, overriding any values already in the environment. Projects can then write `user: "${UID}:${GID}"`. This is refused unless `--allow-me` is given.

## Config file

- Format: TOML, read with `tomllib`. The project requires Python 3.11 for it.
- Locations: `/etc/dockscreen/config.toml` and `$XDG_CONFIG_HOME/dockscreen/config.toml` (default `~/.config/dockscreen/config.toml`). The user file overrides `/etc` key by key, and `image_users` entry by entry.
- Unknown keys are an error, so a typo fails loudly instead of silently dropping a rule.
- Strict modes, like ssh's `StrictModes`: the file and every directory above it must be owned by me or root, and not writable by group or others. Otherwise refuse to run, naming the file.
- An agent running as me can still write a file I own. Only a root-owned file in `/etc` (or `chattr +i`) protects against that.

Keys:

| Key | Default | Meaning |
|---|---|---|
| `default_user` | `"65534:65534"` | used instead of an image's root user |
| `nobody_range` | `[65530, 65534]` | ids any image or project may use, inclusive |
| `mount_dirs` | `[]` | absolute directories, besides the project, that bind mounts may come from |
| `docker` | the next `docker` on `PATH` that is not the wrapper | absolute path of the real docker; a relative path is an error. Strict modes cover the config file, not this binary: whoever can replace it runs code as me, as with any binary on `PATH` |
| `[image_users]` | empty | `repository = "uid:gid"`, without tag or digest |

```toml
default_user = "65534:65534"
nobody_range = [65530, 65534]
mount_dirs = ["/xchange/daniel/data"]

[image_users]
"docker.io/library/mariadb" = "999:999"
```

## Mount roots and the project directory

- **Configured mount dirs:** compare real paths after resolving symlinks. Warn on every run, but don't fail, when a mount dir equals or contains any of these:
  - `/`, `/etc`, `/usr`, `/var`, `/boot`, `/root`, `/run`, `/proc`, `/sys`, `/dev`;
  - `$HOME`;
  - the config file;
  - the docker socket.

  The check is a handful of `realpath` calls and prefix comparisons.
- **Finding the project directory:** the upward search for a compose file stops at `$HOME` and at the first directory that I don't own. Finding the compose file in either of those is an error. A project directory that equals or contains one of the sensitive paths above is refused.

## Notices

One line per service on every run, whenever something other than the service or the command line chose the user:

- the default user replaced root.

An image user from the config file, root included, gets no per-run notice. `audit` lists it.

When the configured default user is root, a notice is printed on every run.

## Open questions

- Pinning an exact image by digest or image id: this is needed for locally built images. A pulled image has a repo digest; for a multi-arch image, that is the digest of the index. A locally built image has only its image id.
- Where `--allow-me` goes on the compose command line: before the subcommand only, like `--skip-security-gate`, or also after `run`, where it would affect only that container.

## Original notes

# user id override

Simplify and clarify when and how containers can use my uid, and when DCOMPOSE_UID (or DOCKSCREEN_UID, or a uid from a configuration file) would be used.

## docker run/start
Rules for docker run/start/exec, but also for docker compose run/exec with a service name.

### no mounts
* if the image's user is root, map it to the allowed standard uid (nobody, or whatever is configured)
* if the uid exists as a local user (different from the configured allowed one), reject it.
* --user, --as, and --as-me override whatever is in the image, and are trusted

### with mounts
as above, but:
* if the uid is not in the allowed high range (and is different from the configured allowed one), reject it even if it doesn't exist as a local user.

### configuration
* the fallback/allowed uid could be configured per image. that would allow mariadb to run with 99, and my own custom local image to run as whatever I choose. This would require a proper config file, but not a complex one. It would provide an escape hatch for the uid rules. The config file would have to be in the user's home directory or under /etc. Not in the project directory. It must not be writable for agents or mounted (writable) into containers.

## docker compose file
Rules for docker up and friends.

Variables:
* Make UID and GID available as environment variables. 
* Force them to the configured allowed IDs (DCOMPOSE_UID or whatever replaces it), which default to nobody.
* --as-me sets them to the user's own uid and gid instead (and makes them "allowed").
* The overrides generated by harden use $UID and $GID, if the image's default would otherwise be rejected.

Rules:
* The user field can name users, names get resolved (and groups implied) in the same way that --as would do.
* If the image's defaults are acceptable or an implicit or configured override applies, audit and harden output should mention this.
* If there is no explicit User defined for the service, the rules that are used for a bare run/start are applied (including per-image configured uid/gid).
* --allow-me allows the configured user to be the current user. Unlike --as-me, UID and GID are not set to the current user.
