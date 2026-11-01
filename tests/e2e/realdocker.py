"""What the end-to-end tests share: the real docker, the images they use, skipping on unmet preconditions."""

import grp
import os
import pwd
import subprocess
import sys
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROJECTS = Path(__file__).resolve().parent / "projects"
DOCKSCREEN = ROOT / "bin" / "docker"
SYSTEM_CONFIG = "/etc/dockscreen/config.toml"

# The images the projects and tests use, pinned so that their users do not change under the tests.
ALPINE = "alpine:3.20"
REDIS = "redis:7.4-alpine"
NGINX = "nginx:1.27-alpine"
NGINX_UNPRIVILEGED = "nginxinc/nginx-unprivileged:1.27-alpine"  # USER 101

# Images the tests build; removed before and after the session.
WEBAPP_APP = "dockscreen-e2e-webapp-app"  # what compose names the webapp's built app image
OWN_IDS_IMAGE = "dockscreen-e2e/app:own-ids"
SUBORDINATE_IMAGE = "dockscreen-e2e/app:subordinate"
STRANGER_IMAGE = "dockscreen-e2e/app:stranger"  # runs as an id that means nothing on this host
BUILT_IMAGES = (WEBAPP_APP, OWN_IDS_IMAGE, SUBORDINATE_IMAGE, STRANGER_IMAGE)

# The environment pytest was started in. The unit tests' fixtures change os.environ for each test
# (DOCKER_HOST, COLUMNS), and docker has to be reached the way the developer's shell reaches it.
HOST_ENV = dict(os.environ)


class PreconditionWarning(UserWarning):
    """The host lacks something a test needs, so the test is skipped."""


def require(condition: object, reason: str) -> None:
    """Skips the test, with a warning that says why, unless condition holds."""
    if not condition:
        warnings.warn(PreconditionWarning(reason), stacklevel=2)
        pytest.skip(reason)


class Result(NamedTuple):
    status: int
    stdout: str
    stderr: str

    @property
    def output(self) -> str:
        """Returns stdout and stderr: the report and dockscreen's messages."""
        return self.stdout + self.stderr

    @property
    def last_line(self) -> str:
        """Returns the last line of stdout, where --brief puts the verdict."""
        lines = self.stdout.strip().splitlines()
        return lines[-1] if lines else ""


def find_docker() -> str | None:
    """Returns the real docker: DOCKSCREEN_E2E_DOCKER, else the first `docker` on PATH that is not a script.

    dockscreen's wrappers (bin/docker, an installed entry point) are scripts; docker is a binary.
    """
    given = HOST_ENV.get("DOCKSCREEN_E2E_DOCKER")
    if given:
        return given
    for directory in HOST_ENV.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, "docker")
        if not os.path.isabs(directory) or not os.path.isfile(candidate) or not os.access(candidate, os.X_OK):
            continue
        with open(candidate, "rb") as f:
            if f.read(2) != b"#!":
                return candidate
    return None


class RealDocker:
    """The real docker, run directly, for setting up and cleaning up around dockscreen."""

    def __init__(self, binary: str) -> None:
        self.binary = binary

    def __call__(self, *args: str, cwd: Path | None = None) -> Result:
        """Runs docker with args and returns the Result."""
        done = subprocess.run([self.binary, *args], check=False, cwd=cwd, env=HOST_ENV, capture_output=True,
                              text=True, timeout=900)
        return Result(done.returncode, done.stdout, done.stderr)

    def remove_images(self, *images: str) -> None:
        """Removes the images that exist of these; the others are ignored."""
        for image in images:
            self("image", "rm", "--force", image)


def run_dockscreen(binary: str, config_home: Path, args: tuple[str, ...], cwd: Path, config: str,
                   env: dict[str, str] | None) -> Result:
    """Runs bin/docker with args in cwd, with config (TOML) as the user's config file, and returns the Result.

    The config file always names binary as the real docker. env: variables to set on top of HOST_ENV.
    """
    (config_home / "dockscreen").mkdir(mode=0o700)
    config_file = config_home / "dockscreen" / "config.toml"
    config_file.write_text(f"docker = {toml_string(binary)}\n{config}")
    config_file.chmod(0o600)
    run_env = {
        **HOST_ENV,
        "XDG_CONFIG_HOME": str(config_home),
        "NO_COLOR": "1",
        "COLUMNS": "10",  # below the minimum width: report lines stay whole
        "PYTHONIOENCODING": "utf-8",
        **(env or {}),
    }
    done = subprocess.run([sys.executable, str(DOCKSCREEN), *args], check=False, cwd=cwd, env=run_env,
                          capture_output=True, text=True, encoding="utf-8", timeout=900)
    return Result(done.returncode, done.stdout, done.stderr)


def toml_string(text: str) -> str:
    """Returns text as a TOML literal string; a path with a quote in it is not supported."""
    assert "'" not in text, f"cannot write {text!r} as a TOML literal string"
    return f"'{text}'"


def user_exists(uid: int) -> bool:
    """Tells whether this host has a user with uid."""
    try:
        pwd.getpwuid(uid)
    except KeyError:
        return False
    return True


def group_exists(gid: int) -> bool:
    """Tells whether this host has a group with gid."""
    try:
        grp.getgrgid(gid)
    except KeyError:
        return False
    return True


def subordinate_ranges(path: str = "/etc/subuid") -> list[range]:
    """Returns the non-empty id ranges in path (/etc/subuid or /etc/subgid); none if it cannot be read."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    ranges = []
    for line in lines:
        fields = line.split(":")
        if len(fields) == 3 and fields[1].isdigit() and fields[2].isdigit() and int(fields[2]) > 0:
            ranges.append(range(int(fields[1]), int(fields[1]) + int(fields[2])))
    return ranges


def first_subordinate_id(path: str = "/etc/subuid") -> int | None:
    """Returns the first id of the first range in path (/etc/subuid), or None if it has none."""
    ranges = subordinate_ranges(path)
    return ranges[0].start if ranges else None


def free_id(taken: Iterable[int], candidates: range = range(20000, 60000)) -> int | None:
    """Returns an id of candidates that is neither in taken nor a user, group or subordinate id here.

    The candidates are below the nobody range and above alpine's own accounts.
    """
    subordinate = subordinate_ranges("/etc/subuid") + subordinate_ranges("/etc/subgid")
    for candidate in candidates:
        if (candidate not in taken and not user_exists(candidate) and not group_exists(candidate)
                and not any(candidate in r for r in subordinate)):
            return candidate
    return None
