import subprocess

import pytest

from dockscreen.dockerclient import Docker, DockerError, DockerNotFound


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

    plain = Docker.new_for_testing(run)
    monkeypatch.setenv("KEPT", "1")

    plain.context()
    plain.with_env({"UID": "7"}).context()

    assert seen[0] is None  # this process's own environment
    assert seen[1]["UID"] == "7" and seen[1]["KEPT"] == "1"
    assert plain.env is None


class Ps:
    """subprocess.run for `docker ps`: its output, and the command."""

    def __init__(self, out="", code=0, err=""):
        self.out, self.code, self.err = out, code, err
        self.commands = []

    def __call__(self, cmd, **kwargs):
        self.commands.append(cmd)
        return subprocess.CompletedProcess(cmd, self.code, self.out, self.err)


def test_label_values_are_read_from_every_container_with_the_label_running_or_not():
    ps = Ps("/a\n\n/b\n")

    assert Docker.new_for_testing(ps).label_values("project", "proj", "dir") == ["/a", "", "/b"]
    assert ps.commands == [["docker", "ps", "--all", "--filter", "label=project=proj", "--format",
                            '{{.Label "dir"}}']]


def test_docker_failing_to_say_is_an_error():
    with pytest.raises(DockerError, match="daemon down"):
        Docker.new_for_testing(Ps(code=1, err="daemon down")).label_values("project", "proj", "dir")
