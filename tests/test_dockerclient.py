import subprocess

import pytest

from dockscreen import docker_cli, runtime
from dockscreen.dockerclient import Docker, DockerNotFound


def test_a_missing_binary_is_docker_not_found(tmp_path):
    docker = Docker(str(tmp_path / "no-docker"))

    with pytest.raises(DockerNotFound, match="'docker' not found in PATH"):
        docker.context()
    with pytest.raises(DockerNotFound):
        docker.read_file("c1", "/etc/passwd")
    with pytest.raises(DockerNotFound):
        docker.start("c1", attach=True, interactive=False, detach_keys=None)


def test_with_env_adds_variables_to_the_environment_of_what_it_runs(monkeypatch):
    seen = []
    def run(cmd, **kwargs):
        seen.append(kwargs.get("env"))
        return subprocess.CompletedProcess(cmd, 0, "default\n", "")

    plain = Docker("docker")
    plain._run_proc = run
    monkeypatch.setenv("KEPT", "1")

    plain.context()
    plain.with_env({"UID": "7"}).context()

    assert seen[0] is None  # this process's own environment
    assert seen[1]["UID"] == "7" and seen[1]["KEPT"] == "1"
    assert plain.env is None


def test_the_docker_wrapper_reports_a_missing_binary_without_a_traceback(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(runtime, "_real_docker", lambda settings, env: str(tmp_path / "no-docker"))

    assert docker_cli.main(["run", "img"]) == 1
    assert capsys.readouterr().err == "[dockscreen] 'docker' not found in PATH\n"
