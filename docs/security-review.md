# Security review: dcompose at a32a493

Audience: whoever fixes the findings below. Commit reviewed: a32a493.

Threat model: the compose project and the image are hostile, and the command line is trusted. Running as root must be rare and strictly opt-in. Running as the calling user ("me") should be easy, but not automatic under the control of a compose file or image.

Uncommitted work-in-progress existed at the time of review, in `gate`, `imageuser`, `runargs`, `hardening` and the new `hostusers.py`. Where it changes a finding, that is noted. Docker was not run. The behaviour of Compose and moby comes from reading their current source on `main`.

## High

### 1. Compose interpolates the generated config a second time, so a checked value can turn into a different one (`composerun`)

`docker compose config` prints values without re-escaping `$`. compose-go's `Project.MarshalJSON` does no escaping. Compose escapes `${` only when it writes bake files (`build_bake.go`).

dcompose writes that output back to a file and runs Compose on it. Compose interpolates the file again, and reloads `.env` from the pinned `--project-directory`. A `$$` in the project survives the first pass as a literal `$`, so the value that was checked is not the value that runs.

Examples, with no `.env` needed thanks to `:-` defaults:

- `pid: "$${P:-host}"` is checked as the literal `${P:-host}`, which isn't `host`, so it passes. It then runs with the host PID namespace. `network_mode` and `ipc` work the same way.
- A bind source of `./$${X:-../../..}` is checked as `/proj/${X:-../../..}`, which is inside the project. It then mounts `/proj/../../..`.

The same second pass happens for `config --services` and for the pulls and builds in `audit` and `harden`. The README's "what was checked is exactly what runs" does not hold.

Fix: escape every `$` as `$$` in string values when writing the generated file, and add a test. As a safety net, run `config` on the generated file and refuse unless the result equals what was checked.

### 2. The Python copy of moby's user lookup differs from moby, and some differences hand an image root (`imageuser.resolve`, compared with `moby/sys/user`)

- Line splitting: Python's `splitlines()` also breaks on `\x1c`–`\x1e`, `\x85`, ` `, `\v` and `\f`, but moby breaks only on `\n`. So `junk\x1capp:x:70000:…` followed by `app:x:0:0` reads as uid 70000 to dcompose and uid 0 to docker.
- Whitespace: moby strips leading and trailing whitespace from every line, and Python doesn't.
  - `  app:x:0:0` placed before `app:x:70000:70000` gives root.
  - A trailing space after a member in `/etc/group` (`root:x:0:app␠`) puts `app` in gid 0 for docker, but not for dcompose.
- Bad numbers: moby ignores `Atoi` errors and zero-fills short lines, so `app:x` or `app:x:+0:…` means uid 0 to moby. Python skips such a line, and a well-formed `app` line after it gives dcompose 70000 while docker uses 0.
- Numeric specs: for a numeric `USER`, moby `main` matches by uid only, while Python also matches a line whose name is that number. Older runc did match both, so the result depends on the daemon version.

Impact: dcompose reports the image as accepted, and the container runs as uid 0, gid 0 or supplementary gid 0. In compose, the service is then exempted from the user check and runs with no `user:` at all.

Fix: stop the runtime from resolving the user a second time. Once the identity is accepted, pin it as numbers:

- compose: `user: "uid:gid"` in the generated file;
- `docker run`: re-create the container with `--user=uid:gid`, as the fallback path already does.

With an explicit numeric group, moby reads neither passwd nor group and adds no supplementary groups. A parser difference can then at worst cause a wrong refusal, never escalation. Aligning the parser (`\n` only, strip whitespace, zero-fill) is still worth doing so the messages are accurate.

### 3. `docker run --user 1000` (a uid without a group) lets the image pick the group

`--user 1000` counts as a user given on the command line, so the gate doesn't check the image's user. Docker then takes the gid from the image's passwd entry for uid 1000, or 0 if there isn't one. Because the group wasn't given, the supplementary groups also come from the image's `/etc/group`. So the image can give the container gid 0, which isn't opt-in.

The work-in-progress `hostusers.resolve` fixes this for names, by adding the host's primary group, but leaves numeric uids without a group.

Fix: add the host's primary gid, or refuse a uid without a group, as the compose policy already does.

## Medium

### 4. A compose file can make a container run as the calling user automatically

NOTE: skip for now, needs design work, not just a security patch.

`user: "${UID}:${GID}"`, or the literal ids, is accepted silently. That is the project choosing "me", which the threat model rules out. It also matters because the project directory is mounted read-write, so a container running as the calling user can write to `.git/hooks`.

Potential fix, to be discussed: accept the calling user's uid only on an explicit command-line opt-in, such as `dcompose --as-me up` or a per-invocation environment variable. Without it, refuse, or run as nobody.

`harden` also writes `${DCOMPOSE_UID}:${DCOMPOSE_GID}` (`autofix.USER_TEMPLATE`) for images whose own user was refused. It should suggest nobody and mention "me" as the opt-in.

### 5. `composerun` doesn't refuse remote daemons, but the `docker` wrapper does

With `DOCKER_HOST=tcp://…` or a non-default context, mount paths are checked on this host but used on another one. The `realpath` and `is_inside` checks, and the host id checks, mean nothing there.

Fix: apply `docker_cli.is_remote` in `composerun` too.

### 6. Between the check and the run, the image is pinned only by its tag

`pull_policy: never` stops Compose from pulling, but a build or pull elsewhere can retag the image in between.

Fix: pin `image:` to the checked image id (`sha256:…`) in the generated file.

### Still open from earlier rounds

- `include` and `extends` can read an `env_file` from outside the project.
- An `ipam` subnet can overlap the LAN.

### To keep in mind, not actionable for now:
- The project chooses its own name, which reaches other projects' volumes.
- The project mount is read-write, so a container can write files that run on the host, such as `.git/hooks`.

## Low

7. `composeimages.decide` passes the image name to `docker create` without `--`, so a name starting with `-` is read as an option. No way to exploit this was found, because the container is never started. Fix: add `--` before the image name.
8. `imageuser.resolve` reports supplementary groups even when the group is given explicitly, which moby doesn't do. This errs on the safe side: an unnecessary fallback to nobody, or an unnecessary refusal.

## Checked and fine

- `--skip-security-gate` is only recognised before the subcommand.
- Finding the real docker skips empty `PATH` entries and the wrapper itself.
- `verify_split` catches a misread `docker run` command line.
- Pulls and builds happen only after the static checks pass.
- Services that aren't started get nobody as a fail-safe.
- The image's `/etc/passwd` and `/etc/group` are read without starting the container, and are capped at 1 MiB.
- The generated file sits in a private temporary directory: the directory is 0700, and the file is created exclusively with mode 0600.
- An explicit `uid:gid` gets no supplementary groups, so the fallback user and `--current-user` are safe.
- The work-in-progress `hardening` change resolves `user: root` to `0:0`, which the policy still refuses.

## Suggested order

1, then 2 (pinning the numeric ids also covers the `user` half of 2's escalation paths), then 3 and 4.
