# End-to-end tests

These tests run dockscreen's audits against the real docker of your host. They are for developers who
change dockscreen's checks or messages and want to see them hold up against real compose, buildx and
images, which the unit tests only simulate.

They pull a few small images and build the example app image, but they only audit: no container is
started and no bake output is written. The images they build are removed before and after the run.

## Running

From the repository root, as your ordinary user:

```
pytest -m e2e -rs
```

`pytest` alone deselects them. `-rs` lists the skipped tests and why. To run one file or test:

```
pytest -m e2e -rs tests/e2e/test_e2e_run.py
pytest -m e2e -rs -k allow_me
```

The tests find the real docker as the first `docker` on `PATH` that is not a script, so dockscreen's own
`bin/docker` and an installed entry point are passed over. If that finds the wrong one, name it:

```
DOCKSCREEN_E2E_DOCKER=/usr/bin/docker pytest -m e2e -rs
```

## Preconditions

Each test checks what it needs first and is skipped with a `PreconditionWarning` if the host lacks it.

All of them need:

- docker with a reachable daemon, on the default context, and `DOCKER_HOST` unset or a `unix://` socket
- `docker compose`
- to run as a user other than root
- no `/etc/dockscreen/config.toml`, which would change what dockscreen allows
- a home directory that nobody else can write to, nor any directory above it: the tests write their
  config files below it, and dockscreen does not read a config file from a place others can write to

Some need more:

- a registry to pull from: `alpine`, `redis`, `nginx` and `nginx-unprivileged`, at pinned tags
- uid and gid between 1000 and 60000, for the app image built with your ids
- a range in `/etc/subuid`, for the image whose user is a subordinate id
- a local user 101, for the test that nginx-unprivileged (which runs as 101) is refused for it
- an id between 20000 and 60000 that is no user, group or subordinate id, for the app image built to run
  as a stranger to the host
- `docker buildx` for the bake tests, and `bake --call` for the one that passes
- compose 2.24 or newer for the harden test, whose patch uses `!reset` and `!override`

## Layout

- `projects/webapp`: a compose project of the usual kind: an app built from the `Dockerfile` with your
  ids, redis, nginx and a mail catcher behind a profile. `compose.debug.yaml` is an override that asks
  for too much, `docker-bake.hcl` has a target that writes to the host and one that uses the host's
  cache, secrets and SSH agent.
- `projects/monitoring`: cAdvisor and the node exporter, set up as their documentation says, which reach
  into the host in most of the ways dockscreen refuses.
- `test_e2e_compose.py`: `compose audit` and `compose harden` on those projects.
- `test_e2e_run.py`: `audit` of what `docker run` would do, for images with various users.
- `test_e2e_bake.py`: `buildx bake` on the webapp's bake file.
- `conftest.py`: the fixtures, which check the preconditions.
- `realdocker.py`: what the fixtures and tests share: the image names, running dockscreen with a config
  file of its own, `require()`.

Each test copies the project it uses to a temporary directory, so a test may change it.

## Writing a test

- Audit, never run: a test that starts a container or writes a bake output does not belong here.
- Check an assumption about the host with `require(condition, reason)` before relying on it, rather
  than letting the test fail.
- Prefer the existing projects and images. Change them only in ways a real project might look.
- Pin new images to a tag, so their users don't change under the tests.
- Pass dockscreen's config as TOML through the `dockscreen` fixture's `config`; never rely on the
  developer's own config file.
