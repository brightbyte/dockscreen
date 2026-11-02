"""Fixtures for the end-to-end tests: dockscreen's audits against the real docker of this host.

They run only when asked for, with `pytest -m e2e`. Each one checks what it needs of the host first
(docker, network access to pull, ids, accounts) and is skipped with a PreconditionWarning if that is
missing. dockscreen reads a config file the tests write, under a temporary directory in your home
directory; a system config file (/etc/dockscreen/config.toml) skips them all, because it would change
the results.
"""

import importlib.util
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from realdocker import (
    ALPINE,
    BUILT_IMAGES,
    COVERAGE_DIR,
    COVERAGE_RC,
    HOST_ENV,
    ODD_IMAGES,
    OWN_IDS_IMAGE,
    PROJECTS,
    STRANGER_IMAGE,
    SUBORDINATE_IMAGE,
    SYSTEM_CONFIG,
    PreconditionWarning,
    RealDocker,
    find_docker,
    first_subordinate_id,
    free_id,
    require,
    write_handoff_script,
)
from steps import LABEL, World


@pytest.fixture(scope="session")
def docker() -> Iterator[RealDocker]:
    """The real docker, once the host is known to suit the tests; the images they build are removed
    before and after.
    """
    binary = find_docker()
    require(binary, "no docker on PATH; set DOCKSCREEN_E2E_DOCKER to the real docker")
    assert binary is not None
    require(os.getuid() != 0, "the tests run as root, but dockscreen's id rules are about an ordinary user")
    require(not os.path.exists(SYSTEM_CONFIG),
            f"{SYSTEM_CONFIG} exists and would change what dockscreen allows")
    host = HOST_ENV.get("DOCKER_HOST", "")
    require(not host or host.startswith("unix://"),
            f"DOCKER_HOST={host} is not a local socket, and dockscreen refuses remote daemons")
    _start_coverage()
    real = RealDocker(binary)
    require(real("info").status == 0, "docker info failed: no daemon is reachable")
    context = real("context", "show").stdout.strip()
    require(context == "default", f"docker's context is {context!r}; dockscreen only screens the default one")
    require(real("compose", "version").status == 0, "docker compose is not installed")
    real.remove_images(*BUILT_IMAGES)  # built anew with the current ids and fixtures
    _remove_labelled_containers(real)
    yield real
    _remove_labelled_containers(real)
    real.remove_images(*BUILT_IMAGES)


@pytest.fixture(scope="session")
def pulled(docker: RealDocker) -> Callable[[str], str]:
    """Returns pull(image), which pulls image once and returns it, or skips the test if it cannot."""
    outcome: dict[str, bool] = {}

    def pull(image: str) -> str:
        if image not in outcome:
            outcome[image] = docker("pull", "--quiet", image).status == 0
        require(outcome[image], f"cannot pull {image}; is the registry reachable?")
        return image

    return pull


@pytest.fixture(scope="session")
def me() -> tuple[int, int]:
    """The (uid, gid) the tests run as."""
    return os.getuid(), os.getgid()


@pytest.fixture(scope="session")
def ordinary_ids(me: tuple[int, int]) -> tuple[int, int]:
    """The caller's (uid, gid), if an image can be built with them: alpine has no account in that range."""
    require(all(1000 <= i < 60000 for i in me),
            f"your ids {me[0]}:{me[1]} are not between 1000 and 60000, where the app image creates its user")
    return me


def _build_app(docker, pulled, tag, uid, gid):
    """Builds the webapp's app image as tag, with its user's ids uid and gid."""
    pulled(ALPINE)
    built = docker("build", "--quiet", "--build-arg", f"UID={uid}", "--build-arg", f"GID={gid}", "--tag", tag,
                   str(PROJECTS / "webapp"))
    assert built.status == 0, built.stderr
    return tag


@pytest.fixture(scope="session")
def own_ids_image(docker, pulled, ordinary_ids):
    return _build_app(docker, pulled, OWN_IDS_IMAGE, *ordinary_ids)


@pytest.fixture(scope="session")
def subordinate_image(docker, pulled):
    first = first_subordinate_id()
    require(first is not None, "/etc/subuid has no range")
    return _build_app(docker, pulled, SUBORDINATE_IMAGE, first, first)


@pytest.fixture(scope="session")
def stranger_image(docker, pulled, me):
    """The app image, run as an id that is no account, group or subordinate id here, nor yours."""
    free = free_id(me)
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    return _build_app(docker, pulled, STRANGER_IMAGE, free, free), free


@pytest.fixture(scope="session")
def odd_image(docker: RealDocker, pulled: Callable[[str], str], me: tuple[int, int],
              tmp_path_factory: pytest.TempPathFactory) -> Callable[[str], tuple[str, int]]:
    """Returns build(tag), which builds the image of ODD_IMAGES with that tag once and returns (tag, the id
    that stands for FREE in it).
    """
    free = free_id(me)
    built: set[str] = set()

    def build(tag: str) -> tuple[str, int]:
        require(free is not None,
                "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
        if tag not in built:
            if ALPINE in ODD_IMAGES[tag]:
                pulled(ALPINE)
            context = tmp_path_factory.mktemp("odd-image")
            (context / "marker").write_text("")
            (context / "Dockerfile").write_text(ODD_IMAGES[tag].replace("FREE", str(free)))
            result = docker("build", "--quiet", "--tag", tag, str(context))
            assert result.status == 0, result.stderr
            built.add(tag)
        return tag, free

    return build


@pytest.fixture(scope="session")
def config_root() -> Iterator[Path]:
    """A directory for the tests' config files, which dockscreen trusts only where nobody else can write.

    /tmp is writable by everyone, so it is in your home directory.
    """
    home = Path.home().resolve()  # dockscreen checks the real path
    unsafe = [p for p in (home, *home.parents) if _writable_by_others(p)]
    require(not unsafe, f"{unsafe[0] if unsafe else ''} is writable by others or not yours, so dockscreen "
                        "would not read a config file below it")
    root = Path(tempfile.mkdtemp(prefix=".dockscreen-e2e-", dir=home))
    yield root
    shutil.rmtree(root)


def _writable_by_others(path: Path) -> bool:
    """Tells whether path is owned by neither the caller nor root, or is writable by group or others."""
    info = path.stat()
    return info.st_uid not in (os.getuid(), 0) or bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


@pytest.fixture(scope="session")
def handoff(config_root: Path) -> Path:
    """The docker that dockscreen runs: handoff.py, which holds back the hand-off (see there)."""
    directory = config_root / "bin"
    directory.mkdir(mode=0o700)
    return write_handoff_script(directory)


@pytest.fixture
def world(request: pytest.FixtureRequest, docker: RealDocker, handoff: Path, config_root: Path,
          tmp_path: Path,
          pulled: Callable[[str], str]) -> Iterator[World]:
    """The World of one scenario (steps.World), whose containers are removed after it."""
    config_home = Path(tempfile.mkdtemp(dir=config_root))
    scenario = World(docker, handoff, tmp_path, config_home, pulled, request.node.nodeid)
    yield scenario
    scenario.remove_containers()


def _remove_labelled_containers(docker: RealDocker) -> None:
    """Removes the containers that scenarios created (steps.LABEL), left over if a run was interrupted."""
    found = docker("ps", "--all", "--quiet", "--filter", f"label={LABEL}").stdout.split()
    if found:
        docker("rm", "--force", *found)


_measuring = False  # whether coverage is measured in this session


def _start_coverage() -> None:
    """Sets up coverage.py for the dockscreen processes, if DOCKSCREEN_E2E_COVERAGE asks for it."""
    global _measuring
    shutil.rmtree(COVERAGE_DIR, ignore_errors=True)
    if HOST_ENV.get("DOCKSCREEN_E2E_COVERAGE") != "1":
        return
    if importlib.util.find_spec("coverage") is None:
        warnings.warn(PreconditionWarning("DOCKSCREEN_E2E_COVERAGE is set, but coverage is not installed"))
        return
    COVERAGE_DIR.mkdir()
    _measuring = True
    # execv: dockscreen hands many commands to docker by replacing itself, and coverage has to save first
    COVERAGE_RC.write_text(f"""[run]
branch = true
parallel = true
data_file = {COVERAGE_DIR / "data"}
source_pkgs = dockscreen
patch = execv

[report]
show_missing = true
skip_covered = true
omit = */dockscreen/helptext.py
""")


def pytest_terminal_summary(terminalreporter: Any) -> None:
    """Reports the coverage of dockscreen by the scenarios, when it was measured."""
    if not _measuring:
        return
    coverage = [sys.executable, "-m", "coverage"]
    subprocess.run([*coverage, "combine", f"--rcfile={COVERAGE_RC}"], capture_output=True, check=False)
    report = subprocess.run([*coverage, "report", f"--rcfile={COVERAGE_RC}"], capture_output=True, text=True,
                            check=False)
    subprocess.run([*coverage, "html", f"--rcfile={COVERAGE_RC}", f"--directory={COVERAGE_DIR / 'html'}"],
                   capture_output=True, check=False)
    terminalreporter.section("dockscreen coverage by the end-to-end tests")
    terminalreporter.write(report.stdout + report.stderr)
    terminalreporter.write_line(f"HTML report: {COVERAGE_DIR / 'html' / 'index.html'}")
