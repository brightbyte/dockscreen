"""The steps the end-to-end scenarios are written in, after the fashion of pytest-bdd without Gherkin.

A scenario is a test function that reads as Given, When, Then:

    def test_a_privileged_service_is_refused(world):
        given_service(world, "app", privileged=True)
        when_dockscreen(world, "compose", "up")
        then_refused(world, "service app: privileged is not allowed")
        then_nothing_handed_off(world)

The steps share a World (the `world` fixture), as behave's steps share a context: what the scenario set up
(the project, the config file, the environment) and what happened when dockscreen ran (its Result, and the
calls it made to docker). A step that fails says what dockscreen printed and which calls it made.

Given steps set up the project and the host; a compose file is written as JSON, which is YAML, when
dockscreen runs. When steps run dockscreen, through handoff.py, which holds back the hand-off to docker.
Then steps check the outcome. A Scenario Outline is a scenario with `@pytest.mark.parametrize`, its
Examples given ids that read as the example's name.
"""

import hashlib
import json
import os
import pwd
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

from realdocker import (
    ALPINE,
    PROJECTS,
    Call,
    RealDocker,
    Result,
    read_calls,
    require,
    run_dockscreen,
    toml_string,
)

# What ends dockscreen's output, by verdict (screen.report).
PASSED, REFUSED, FAILED = "✔ audit passed", "⊖ denied by audit", "✘ audit failed"
# Labels the containers the scenarios create themselves, so that they can be found and removed.
LABEL = "dockscreen-e2e"


class World:
    """State of a scenario: its setup, and the result of running dockscreen."""

    def __init__(self, docker: RealDocker, handoff: Path, base: Path, config_home: Path,
                 pull: Callable[[str], str], nodeid: str) -> None:
        self.docker = docker
        self.handoff = handoff         # the docker dockscreen runs (handoff.py)
        self.base = base               # the scenario's own directory
        self.project_dir = base / "project"
        self.project_dir.mkdir()
        self.cwd = self.project_dir    # where dockscreen runs
        # a compose project name of the scenario's own, so that projects of other scenarios never clash
        self.name = "dse2e-" + hashlib.sha256(nodeid.encode()).hexdigest()[:10]
        self.compose: dict[str, Any] | None = None  # written to compose.yaml when dockscreen runs, if set
        self.config_file = config_home / "dockscreen" / "config.toml"
        self.config = ""               # TOML for the config file, after the line that names the docker
        self.config_text: str | None = None  # the whole config file instead, if set
        self.no_config = False         # leave no config file at all
        self.env: dict[str, str] = {}
        self.pull = pull
        self.result: Result | None = None
        self.calls: list[Call] = []
        self.containers: list[str] = []  # created during the scenario, removed after it
        self._runs = 0

    def run(self, *args: str) -> Result:
        """Runs dockscreen with args, and keeps its Result and the calls it made."""
        if self.compose is not None:
            # without \u escapes, which compose's YAML parser reads only in the Basic Multilingual Plane
            text = json.dumps(self.compose, indent=2, ensure_ascii=False)
            (self.project_dir / "compose.yaml").write_text(text, encoding="utf-8")
        self._runs += 1
        calls = self.base / f"calls-{self._runs}.jsonl"
        self.result = run_dockscreen(args, self.cwd, self.config_file, self._config(), self.env,
                                     self.docker.binary, calls)
        self.calls = read_calls(calls)
        self.containers += [c.created for c in self.calls if c.created]
        return self.result

    def _config(self) -> str | None:
        """Returns the text of the config file, or None for none."""
        if self.no_config:
            return None
        if self.config_text is not None:
            return self.config_text
        return f"docker = {toml_string(str(self.handoff))}\n{self.config}"

    def report(self) -> str:
        """Describes the last run, for a step that fails."""
        if self.result is None:
            return "dockscreen did not run"
        calls = "\n".join(("HELD " if c.held else "     ") + " ".join(c.argv) for c in self.calls)
        return (f"exit status {self.result.status}\n--- stdout\n{self.result.stdout}--- stderr\n"
                f"{self.result.stderr}--- calls to docker\n{calls}")

    @property
    def output(self) -> str:
        """Returns what the last run printed, stdout and stderr."""
        assert self.result is not None, "dockscreen did not run"
        return self.result.output

    def handoffs(self) -> list[Call]:
        """Returns the calls of the last run that handoff.py held back."""
        return [c for c in self.calls if c.held]

    def remove_containers(self) -> None:
        """Removes the containers the scenario created."""
        if self.containers:
            self.docker("rm", "--force", *self.containers)


# --- Given ---------------------------------------------------------------------------------------------

def given_service(world: World, name: str = "app", keys: dict[str, Any] | None = None, **more: Any) -> None:
    """Given a service called name in the project, of alpine unless keys or more set an image or build.

    keys: for keys that are not Python names, such as `x-bake`; more: the others.
    """
    service = {**(keys or {}), **more}
    if "image" not in service and "build" not in service:
        service["image"] = ALPINE
    _compose(world).setdefault("services", {})[name] = service


def given_compose(world: World, key: str, value: Any) -> None:
    """Given the top-level key of the compose file set to value."""
    _compose(world)[key] = value


def _compose(world: World) -> dict[str, Any]:
    """Returns the compose file of the world, started with the project's name."""
    if world.compose is None:
        world.compose = {"name": world.name}
    return world.compose


def given_example_project(world: World, name: str) -> None:
    """Given a copy of the example project of that name (tests/e2e/projects) as the project."""
    shutil.rmtree(world.project_dir)
    shutil.copytree(PROJECTS / name, world.project_dir, symlinks=True)


def given_file(world: World, path: str, text: str = "") -> Path:
    """Given a file at path in the project (or, absolute, anywhere), with text; returns its path."""
    target = world.project_dir / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    return target


def given_symlink(world: World, path: str, target: str | Path) -> Path:
    """Given a symlink at path in the project that points to target; returns its path."""
    link = world.project_dir / path
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    return link


def given_outside_dir(world: World, name: str = "outside") -> Path:
    """Given a directory of the scenario's own outside the project; returns its path."""
    directory = world.base / name
    directory.mkdir(exist_ok=True)
    return directory


def given_config(world: World, toml: str) -> None:
    """Given a config file that sets toml, besides the real docker."""
    world.config += toml if toml.endswith("\n") else toml + "\n"


def given_project_section(world: World, toml: str) -> None:
    """Given a section of the config file for the project directory, setting toml."""
    given_config(world, f"[projects.{toml_string(str(world.project_dir))}]\n{toml}")


def given_image_section(world: World, repository: str, toml: str) -> None:
    """Given a section of the config file for the image repository, setting toml."""
    given_config(world, f"[images.{toml_string(repository)}]\n{toml}")


def given_env(world: World, **variables: str) -> None:
    """Given these variables in the environment dockscreen runs in."""
    world.env.update(variables)


def given_image(world: World, image: str) -> str:
    """Given image pulled; the scenario is skipped if it cannot be."""
    return world.pull(image)


def given_container(world: World, *args: str, labels: dict[str, str] | None = None) -> str:
    """Given a container created, not started, by plain docker with `docker create args`; returns its id."""
    label_args = [f"--label={key}={value}" for key, value in {LABEL: "1", **(labels or {})}.items()]
    created = world.docker("create", *label_args, *args)
    assert created.status == 0, created.stderr
    container = created.stdout.strip()
    world.containers.append(container)
    return container


def given_project_container(world: World, name: str, working_dir: str | None) -> str:
    """Given a container that compose would have made for a project called name in working_dir (None: a
    container without the label that says where).
    """
    labels = {"com.docker.compose.project": name}
    if working_dir is not None:
        labels["com.docker.compose.project.working_dir"] = working_dir
    return given_container(world, given_image(world, ALPINE), "true", labels=labels)


# --- When ----------------------------------------------------------------------------------------------

def when_dockscreen(world: World, *args: str) -> Result:
    """When dockscreen runs with args (as `docker args`), in the project directory unless world.cwd says."""
    return world.run(*args)


# --- Then ----------------------------------------------------------------------------------------------

def then_status(world: World, status: int) -> None:
    """Then dockscreen exits with status."""
    assert world.result is not None and world.result.status == status, world.report()


def then_passed(world: World) -> None:
    """Then the checks pass: exit status 0, and the closing line says so."""
    then_status(world, 0)
    then_said(world, PASSED)


def then_refused(world: World, *problems: str) -> None:
    """Then the checks refuse, for each of problems: exit status 1, and the closing line says so."""
    then_status(world, 1)
    then_said(world, REFUSED, *problems)


def then_failed(world: World, *problems: str, status: int = 3) -> None:
    """Then the checks fail to get far enough to judge, for each of problems: status 3 for an audit, 1 for
    a command.
    """
    then_status(world, status)
    then_said(world, FAILED, *problems)


def then_said(world: World, *texts: str) -> None:
    """Then dockscreen's output (stdout and stderr) contains each of texts."""
    for text in texts:
        assert text in world.output, f"expected {text!r}\n{world.report()}"


def then_not_said(world: World, *texts: str) -> None:
    """Then dockscreen's output contains none of texts."""
    for text in texts:
        assert text not in world.output, f"did not expect {text!r}\n{world.report()}"


def then_nothing_handed_off(world: World) -> None:
    """Then nothing reached docker that would start, stop or change a container."""
    assert not world.handoffs(), world.report()


def then_nothing_acquired(world: World) -> None:
    """Then no image was pulled or built and no container created: the refusal came first."""
    acquiring = [c for c in world.calls if _acquires(c.argv)]
    assert not acquiring, world.report()


def _acquires(argv: list[str]) -> bool:
    """Tells whether a call pulls or builds an image, or creates a container."""
    return bool({"pull", "build", "create"} & set(argv)) and "config" not in argv


def then_handed_off(world: World, *argv_end: str) -> Call:
    """Then exactly one call reached docker that would start or change containers, and it is returned.

    argv_end: what the call's arguments end with, if given.
    """
    handoffs = world.handoffs()
    assert len(handoffs) == 1, f"expected one hand-off\n{world.report()}"
    call = handoffs[0]
    if argv_end:
        assert call.argv[-len(argv_end):] == list(argv_end), f"expected {argv_end} last\n{world.report()}"
    return call


def then_handed_off_unchanged(world: World, *argv: str) -> None:
    """Then the command reached docker exactly as typed, with nothing held back but itself."""
    call = then_handed_off(world)
    assert call.argv == list(argv), world.report()


def then_passed_through(world: World, *argv: str) -> None:
    """Then the command went to the real docker as typed: dockscreen handed it on unchecked."""
    assert [c.argv for c in world.calls] == [list(argv)], world.report()
    assert not world.calls[0].held, world.report()


def then_generated_service(world: World, name: str = "app") -> dict[str, Any]:
    """Then compose was handed a generated file, and the service called name in it is returned."""
    call = then_handed_off(world)
    services = call.compose_file["services"]
    assert name in services, world.report()
    return services[name]


def then_container(world: World, container: str) -> dict[str, Any]:
    """Then docker has the container, and it is returned as `docker container inspect` gives it."""
    inspected = world.docker("container", "inspect", container)
    assert inspected.status == 0, f"no container {container}\n{world.report()}"
    return json.loads(inspected.stdout)[0]


def then_started_container(world: World) -> dict[str, Any]:
    """Then `docker start` was handed the container that dockscreen created, which is returned inspected."""
    call = then_handed_off(world)
    assert call.argv[0] == "start", world.report()
    return then_container(world, call.last)


def then_runs_hardened(world: World, container: dict[str, Any]) -> None:
    """Then the container drops every capability and cannot gain privileges."""
    host = container["HostConfig"]
    assert [c.upper() for c in host.get("CapDrop") or []] == ["ALL"], world.report()
    assert "no-new-privileges:true" in (host.get("SecurityOpt") or []), world.report()


def home_of(env: list[str] | None) -> str | None:
    """Returns the HOME a container's Env list sets, or None."""
    homes = [e.partition("=")[2] for e in env or [] if e.startswith("HOME=")]
    return homes[-1] if homes else None


def my_ids() -> tuple[int, int]:
    """Returns the (uid, gid) the scenarios run as."""
    return os.getuid(), os.getgid()


def my_name() -> str:
    """Returns the name of the account the scenarios run as; skips the scenario if it has none."""
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        require(False, f"uid {os.getuid()} has no account on this host")
        raise


def me_user() -> str:
    """Returns the caller's ids as `uid:gid`."""
    uid, gid = my_ids()
    return f"{uid}:{gid}"
