import json
import os
import subprocess

import pytest

from dockscreen import bake, docker_cli
from dockscreen.dockerclient import DockerError


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    os.symlink(tmp_path, root / "escape")
    return root


def check(project, **target):
    return bake.check_definition({"group": {"default": {"targets": ["app"]}}, "target": {"app": target}},
                                 str(project))


def test_a_definition_of_ordinary_builds_has_no_problems(project):
    assert check(project, context=".", dockerfile="Dockerfile", args={"A": "1"}, tags=["app:1"],
                 platforms=["linux/amd64"], output=["type=image,push=false"], network="none",
                 contexts={"base": "docker-image://alpine", "lib": "app"},
                 **{"cache-from": ["type=registry,ref=r/app", f"type=local,src=app"],
                    "cache-to": ["type=inline"], "secret": ["id=npm,src=app/.npmrc"]}) == []


@pytest.mark.parametrize("fields, problem", [
    ({"context": "/etc"}, "context '/etc' is outside"),
    ({"context": "escape"}, "context 'escape' is outside"),
    ({"context": ".", "dockerfile": "../x/Dockerfile"}, "dockerfile '../x/Dockerfile' is outside"),
    ({"contexts": {"c": "/etc"}}, "contexts 'c': '/etc' is outside"),
    ({"network": "host"}, "network 'host' is not allowed"),
    ({"entitlements": ["network.host"]}, "entitlements ask for access"),
    ({"ssh": ["default"]}, "ssh forwards your SSH agent"),
    ({"output": ["out"]}, "output 'out' writes to the host"),
    ({"output": ["type=local,dest=/etc"]}, "output 'type=local,dest=/etc' writes to the host"),
    ({"output": ["type=docker,dest=/tmp/x.tar"]}, "writes to the host"),
    ({"cache-to": ["type=local,dest=/etc"]}, "cache-to 'type=local,dest=/etc' writes to the host"),
    ({"cache-to": ["type=s3,bucket=b"]}, "cache-to 'type=s3,bucket=b' writes to the host or an unknown store"),
    ({"cache-from": ["type=local,src=/etc"]}, "cache-from 'type=local,src=/etc' is outside"),
    ({"secret": ["id=k,src=/home/me/.ssh/id_rsa"]}, "secret 'id=k,src=/home/me/.ssh/id_rsa' is outside"),
    ({"secret": ["id=k,env=AWS_SECRET_ACCESS_KEY"]}, "copies a variable"),
    ({"secret": ["id=AWS_SECRET_ACCESS_KEY"]}, "copies a variable"),
    ({"x-bake": {}}, "key 'x-bake' is not on the allow list"),
    ({"newkey": 1}, "key 'newkey' is not on the allow list"),
])
def test_what_a_build_could_reach_on_the_host_is_refused(project, fields, problem):
    problems = check(project, **{"context": ".", **fields} if "context" not in fields else fields)
    assert len(problems) == 1 and problem in problems[0], problems
    assert problems[0].startswith("target app: ")


def test_a_top_level_key_that_is_not_known_is_refused(project):
    assert bake.check_definition({"target": {}, "variable": {}}, str(project)) == [
        "key 'variable' is not on the allow list"]


@pytest.mark.parametrize("args, screened", [
    (["app"], True),
    (["-f", "docker-bake.hcl", "--set", "*.output=out", "--push"], True),
    (["--print"], False),
    (["--help"], False),
    (["-h"], False),
])
def test_only_a_bake_that_builds_is_screened(args, screened):
    assert bake.wants_screening(args) is screened


class Docker:
    binary = "docker"

    def __init__(self, code=0, out="{}", err=""):
        self.result = subprocess.CompletedProcess([], code, out, err)
        self.commands = []

    def run(self, cmd, **kwargs):
        self.commands.append(cmd)
        return self.result


def test_the_definition_comes_from_print_with_the_arguments_of_the_command():
    docker = Docker(out=json.dumps({"target": {}}))

    assert bake.definition(docker, ["-f", "b.hcl", "app"]) == {"target": {}}
    assert docker.commands == [["docker", "buildx", "bake", "--print", "-f", "b.hcl", "app"]]


@pytest.mark.parametrize("docker, message", [
    (Docker(code=1, err="no bake file"), "no bake file"),
    (Docker(out="not json"), "cannot read the bake definition"),
    (Docker(out="[]"), "cannot read the bake definition: not an object"),
])
def test_a_definition_that_cannot_be_read_fails_the_screening(docker, message):
    with pytest.raises(DockerError, match=message):
        bake.definition(docker, [])
    reasons, failed = bake.screen(docker, [])
    assert failed and message in reasons[0]


def test_screen_checks_against_the_current_directory(project, monkeypatch):
    monkeypatch.chdir(project)
    docker = Docker(out=json.dumps({"target": {"app": {"context": "/etc"}}}))

    assert bake.screen(docker, []) == (["target app: context '/etc' is outside " + str(project)], False)


@pytest.mark.parametrize("argv, args", [
    (["buildx", "bake", "app"], ["app"]),
    (["buildx", "--builder", "b", "bake", "-f", "x.hcl"], ["-f", "x.hcl"]),
    (["buildx", "build", "."], None),
    (["buildx", "bake"], []),
    (["build", "."], None),
    (["run", "bake"], None),
])
def test_bake_arguments_are_taken_from_buildx_bake_only(argv, args):
    assert docker_cli.bake_arguments(argv, 0) == args


@pytest.mark.parametrize("reasons, failed, passed", [([], False, True), (["no"], False, False), (["x"], True, False)])
def test_bake_runs_only_when_screening_passes(monkeypatch, reasons, failed, passed):
    calls = []
    monkeypatch.setattr(docker_cli, "passthrough", lambda argv, runtime: calls.append(argv) or 0)
    monkeypatch.setattr(docker_cli.bake, "screen", lambda docker, args: (reasons, failed))

    code = docker_cli.main(["buildx", "bake", "app"])

    assert (calls == [["buildx", "bake", "app"]]) is passed
    assert (code == 0) is passed


def test_bake_print_is_not_screened(monkeypatch):
    calls = []
    monkeypatch.setattr(docker_cli, "passthrough", lambda argv, runtime: calls.append(argv) or 0)
    monkeypatch.setattr(docker_cli.bake, "screen", lambda *a: 1 / 0)

    docker_cli.main(["buildx", "bake", "--print"])

    assert calls == [["buildx", "bake", "--print"]]
