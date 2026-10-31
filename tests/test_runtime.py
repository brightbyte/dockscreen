import os

import pytest

from dockscreen import config, docker_cli, runtime
from dockscreen.dockerclient import DockerNotFound

REAL_DOCKER = runtime._real_docker  # conftest replaces it for every test


def make_docker(directory):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "docker"
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


def test_skips_our_own_wrapper_even_through_a_symlink(tmp_path):
    wrapper = make_docker(tmp_path / "wrapper")
    link_dir = tmp_path / "front"
    link_dir.mkdir()
    os.symlink(wrapper, link_dir / "docker")
    real = make_docker(tmp_path / "real")
    env = {"PATH": os.pathsep.join([str(link_dir), str(tmp_path / "wrapper"), str(tmp_path / "real")])}

    assert runtime._find_docker(env, {os.path.realpath(wrapper)}) == str(real)


def test_the_configured_path_wins(tmp_path):
    make_docker(tmp_path / "real")
    env = {"PATH": str(tmp_path / "real")}
    assert REAL_DOCKER(config.Config(docker="/opt/docker"), env, set()) == "/opt/docker"
    assert REAL_DOCKER(config.Config(), env, set()) == str(tmp_path / "real" / "docker")
    with pytest.raises(DockerNotFound):
        REAL_DOCKER(config.Config(), {"PATH": ""}, set())


def test_empty_and_relative_entries_are_never_searched(tmp_path, monkeypatch):
    make_docker(tmp_path / "bin")
    monkeypatch.chdir(tmp_path)
    assert runtime._find_docker({"PATH": os.pathsep.join(["", ".", "bin", "./bin"])}, set()) is None
    assert runtime._find_docker({"PATH": os.pathsep.join(["bin", str(tmp_path / "bin")])}, set()) == \
        str(tmp_path / "bin" / "docker")


@pytest.mark.parametrize("path, warned", [
    ("/usr/local/bin:/usr/bin", False),
    ("/usr/bin::/bin", True),
    ("/usr/bin:.", True),
    ("bin:/usr/bin", True),
])
def test_empty_or_relative_path_entries_are_warned_about(monkeypatch, capsys, path, warned):
    monkeypatch.setenv("PATH", path)
    monkeypatch.setattr(config, "load_current", lambda env, home, uid: config.Config())
    runtime.load_runtime()
    assert ("PATH has empty or relative entries" in capsys.readouterr().err) == warned


def test_nothing_found(tmp_path):
    assert runtime._find_docker({"PATH": str(tmp_path)}, set()) is None


def test_without_a_real_docker_dockscreen_stops_instead_of_running_itself(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(runtime, "_real_docker", REAL_DOCKER)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert docker_cli.main(["ps"]) == 1
    assert capsys.readouterr().err == "[dockscreen] 'docker' not found in PATH\n"
