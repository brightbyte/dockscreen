import os

from dockscreen import config, runtime

REAL_DOCKER = runtime.real_docker  # conftest replaces it for every test


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

    assert runtime.find_docker(env, {os.path.realpath(wrapper)}) == str(real)


def test_the_configured_path_wins(tmp_path):
    make_docker(tmp_path / "real")
    env = {"PATH": str(tmp_path / "real")}
    assert REAL_DOCKER(config.Config(docker="/opt/docker"), env, set()) == "/opt/docker"
    assert REAL_DOCKER(config.Config(), env, set()) == str(tmp_path / "real" / "docker")
    assert REAL_DOCKER(config.Config(), {"PATH": ""}, set()) == "docker"


def test_current_directory_is_never_searched(tmp_path, monkeypatch):
    make_docker(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert runtime.find_docker({"PATH": os.pathsep.join(["", "."])}, set()) is None or \
        runtime.find_docker({"PATH": os.pathsep.join(["", "."])}, set()) == "./docker"
    assert runtime.find_docker({"PATH": os.pathsep.join(["", str(tmp_path / "nothing")])}, set()) is None


def test_nothing_found(tmp_path):
    assert runtime.find_docker({"PATH": str(tmp_path)}, set()) is None
