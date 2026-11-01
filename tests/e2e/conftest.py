"""Fixtures for the end-to-end tests: dockscreen's audits against the real docker of this host.

They run only when asked for, with `pytest -m e2e`. Each one checks what it needs of the host first
(docker, network access to pull, ids, accounts) and is skipped with a PreconditionWarning if that is
missing. dockscreen reads a config file the tests write, under a temporary directory in your home
directory; a system config file (/etc/dockscreen/config.toml) skips them all, because it would change
the results.
"""

import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from realdocker import (
    BUILT_IMAGES,
    HOST_ENV,
    PROJECTS,
    SYSTEM_CONFIG,
    RealDocker,
    Result,
    find_docker,
    require,
    run_dockscreen,
)


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
    real = RealDocker(binary)
    require(real("info").status == 0, "docker info failed: no daemon is reachable")
    context = real("context", "show").stdout.strip()
    require(context == "default", f"docker's context is {context!r}; dockscreen only screens the default one")
    require(real("compose", "version").status == 0, "docker compose is not installed")
    real.remove_images(*BUILT_IMAGES)  # built anew with the current ids and fixtures
    yield real
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


@pytest.fixture
def dockscreen(docker: RealDocker, config_root: Path) -> Callable[..., Result]:
    """Returns run(*args, cwd, config="", env=None), which runs dockscreen with a config file of its own.

    config: TOML for the config file, which also names the real docker. env: variables to set.
    """
    def run(*args: str, cwd: Path, config: str = "", env: dict[str, str] | None = None) -> Result:
        config_home = Path(tempfile.mkdtemp(dir=config_root))
        return run_dockscreen(docker.binary, config_home, args, cwd, config, env)

    return run


@pytest.fixture
def project(tmp_path: Path) -> Callable[[str], Path]:
    """Returns copy(name), which copies the project of that name to a directory of the test's own."""
    def copy(name: str) -> Path:
        return Path(shutil.copytree(PROJECTS / name, tmp_path / name, symlinks=True))

    return copy

