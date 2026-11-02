# End-to-end tests

These tests characterize dockscreen against the real docker of your host: every check it makes, written
as a scenario of what a project, an image or a command line asks for and what dockscreen does about it.
They are for developers who change dockscreen, and for whoever reviews its security: the unit tests
simulate docker and compose, and these show that the checks hold up against the real ones.

Nothing starts. dockscreen runs the real docker through `handoff.py`, which passes every call on except
the hand-off: the call that would start, stop or change containers, or write a build's output, once the
checks have passed. That call is recorded and answered with success, so a scenario sees exactly what
dockscreen would have run (the arguments, the compose file it generated), and can inspect the container
it created for `docker run`. The tests pull a few small images, build the example app image, and create
containers that are never started; all of these are removed after the run.

## Running

From the repository root, as your ordinary user:

```
pytest -m e2e -rs
```

`pytest` alone deselects them. `-rs` lists the skipped tests and why. To run one feature or scenario:

```
pytest -m e2e -rs tests/e2e/test_e2e_docker_run.py
pytest -m e2e -rs -k allow_me
```

The tests find the real docker as the first `docker` on `PATH` that is not a script, so dockscreen's own
`bin/docker` and an installed entry point are passed over. If that finds the wrong one, name it:

```
DOCKSCREEN_E2E_DOCKER=/usr/bin/docker pytest -m e2e -rs
```

### Coverage

```
DOCKSCREEN_E2E_COVERAGE=1 pytest -m e2e -rs
```

runs dockscreen under coverage.py, if it is installed, and ends with a report of the lines and branches of
dockscreen the scenarios did not reach, and an HTML report in `.coverage-e2e/html`. `COVERAGE.md` says
which of those cannot be reached from here, and why.

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
- a local user 101, for the scenarios where nginx-unprivileged (which runs as 101) is refused for it, or no
  user 101, for the one where it is refused only with a host mount
- a local user 1, for the scenario that refuses an account of this host
- an id between 20000 and 60000 that is no user, group or subordinate id, for the app image built to run
  as a stranger to the host, and for the scenarios that need an id that means nothing here
- `docker buildx` for the bake scenarios, and `bake --call` for the one that passes
- compose 2.24 or newer for the harden scenarios, whose patch uses `!reset` and `!override`

## Layout

Each `test_e2e_*.py` is a feature: its docstring states the rules, and each test is a scenario of them,
written in the steps of `steps.py`:

```python
def test_a_privileged_service_is_refused(world):
    given_service(world, "app", privileged=True)
    when_dockscreen(world, "compose", "up")
    then_refused(world, "service app: privileged is not allowed")
    then_nothing_handed_off(world)
```

A scenario outline is a scenario with `@pytest.mark.parametrize`, whose examples have ids that read as
their names.

- `steps.py`: the `World` a scenario builds up and runs dockscreen in, and the Given, When and Then steps.
  A failing Then step shows what dockscreen printed and the calls it made to docker.
- `handoff.py`: the docker that dockscreen runs, which holds back the hand-off and records every call.
- `conftest.py`: the fixtures, which check the preconditions, pull and build images, and measure coverage.
- `realdocker.py`: what the fixtures and steps share: the image names, running dockscreen with a config
  file of its own, `require()`.
- `projects/webapp`: a compose project of the usual kind: an app built from the `Dockerfile` with your
  ids, redis, nginx and a mail catcher behind a profile. `compose.debug.yaml` is an override that asks
  for too much, `docker-bake.hcl` has a target that writes to the host and one that uses the host's
  cache, secrets and SSH agent.
- `projects/monitoring`: cAdvisor and the node exporter, set up as their documentation says, which reach
  into the host in most of the ways dockscreen refuses.

Each scenario has a project directory, a config file and a compose project name of its own, so a scenario
may change them.

## Writing a scenario

- Nothing may start: a call that starts or changes containers must be one that `handoff.py` holds back.
  Add it to `HELD_DOCKER` or `HELD_COMPOSE` before a scenario makes dockscreen hand it on.
- State the rule in the feature's docstring first, then write the scenario against it: what dockscreen
  prints and hands on, not how it gets there.
- Check an assumption about the host with `require(condition, reason)` before relying on it, rather
  than letting the scenario fail.
- Give the compose file as data (`given_service`, `given_compose`); it is written as JSON, which is YAML.
- Prefer the existing projects and images. Pin new images to a tag, so their users don't change under
  the tests.
- Give dockscreen's config as TOML through the Given steps; never rely on the developer's own config file.
