import json
import os
import subprocess

import pytest
from fakes import make_runtime, rules

from dockscreen import docker_cli
from dockscreen.commands import docker_bake
from dockscreen.host.dockerclient import DockerError
from dockscreen.model.build import BakeDefinition
from dockscreen.screen import policy
from dockscreen.screen.findings import Severity
from dockscreen.util import messages


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "project"
    (root / "app").mkdir(parents=True)
    os.symlink(tmp_path, root / "escape")
    return root


def check(project, **target):
    definition = {"group": {"default": {"targets": ["app"]}}, "target": {"app": target}}
    return policy.Policy(str(project), rules()).check_bake(BakeDefinition(definition))


def test_a_definition_of_ordinary_builds_has_no_problems(project):
    assert check(project, context=".", dockerfile="Dockerfile", args={"A": "1"}, tags=["app:1"],
                 platforms=["linux/amd64"], output=["type=image,push=false"], network="none",
                 contexts={"base": "docker-image://alpine", "lib": "app"},
                 **{"cache-from": ["type=registry,ref=r/app", "type=local,src=app"],
                    "cache-to": ["type=inline"], "secret": ["id=npm,src=app/.npmrc"]}) == []


def test_entries_printed_as_objects_are_read_as_their_fields(project):
    assert check(project, context=".", **{
        "cache-from": [{"type": "registry", "ref": "r/app"}, {"type": "local", "src": "app"}],
        "cache-to": [{"type": "inline"}], "secret": [{"id": "npm", "src": "app/.npmrc"}]}) == []


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
    ({"cache-to": ["type=s3,bucket=b"]},
     "cache-to 'type=s3,bucket=b' writes to the host or an unknown store"),
    ({"cache-from": ["type=local,src=/etc"]}, "cache-from 'type=local,src=/etc' is outside"),
    ({"secret": ["id=k,src=/home/me/.ssh/id_rsa"]}, "secret 'id=k,src=/home/me/.ssh/id_rsa' is outside"),
    ({"secret": ["id=k,env=AWS_SECRET_ACCESS_KEY"]}, "copies a variable"),
    ({"secret": ["id=AWS_SECRET_ACCESS_KEY"]}, "copies a variable"),
    # newer buildx prints these as objects
    ({"cache-from": [{"type": "local", "src": "/etc"}]},
     "cache-from {'type': 'local', 'src': '/etc'} is outside"),
    ({"cache-from": [{"type": "local", "src": ["/etc"]}]}, "cannot be read"),
    ({"cache-to": [{"type": "local", "dest": "/etc"}]}, "writes to the host"),
    ({"secret": [{"id": "k", "src": "/home/me/.ssh/id_rsa"}]}, "is outside"),
    ({"secret": [{"id": "k", "env": "AWS_SECRET_ACCESS_KEY"}]}, "copies a variable"),
    ({"x-bake": {}}, "key 'x-bake' is not on the allow list"),
    ({"newkey": 1}, "key 'newkey' is not on the allow list"),
])
def test_what_a_build_could_reach_on_the_host_is_refused(project, fields, problem):
    problems = check(project, **{"context": ".", **fields} if "context" not in fields else fields)
    assert len(problems) == 1 and problem in problems[0], problems
    assert problems[0].startswith("target app: ")


def test_a_top_level_key_that_is_not_known_is_refused(project):
    bake_policy = policy.Policy(str(project), rules())
    found = bake_policy.check_bake(BakeDefinition({"target": {}, "variable": {}}))
    assert found == ["key 'variable' is not on the allow list"]


@pytest.mark.parametrize("args, screened", [
    (["app"], True),
    (["-f", "docker-bake.hcl", "--set", "*.output=out", "--push"], True),
    (["--print"], False),
    (["--help"], False),
    (["-h"], False),
])
def test_only_a_bake_that_builds_is_screened(args, screened):
    assert docker_bake.wants_screening(args) is screened


class Docker:
    """A docker whose `buildx bake --print` gives out, err and code; it records what it would exec."""

    binary = "docker"

    def __init__(self, code=0, out="{}", err=""):
        self.result = subprocess.CompletedProcess([], code, out, err)
        self.commands = []
        self.executed = []

    def capture(self, cmd):
        self.commands.append(cmd)
        return self.result

    def exec(self, args):
        self.executed.append(args)


def test_the_definition_comes_from_print_with_the_arguments_of_the_command():
    docker = Docker(out=json.dumps({"target": {}}))

    assert docker_bake._definition(docker, ["-f", "b.hcl", "app"]) == {"target": {}}
    assert docker.commands == [["docker", "buildx", "bake", "--print", "-f", "b.hcl", "app"]]


@pytest.mark.parametrize("docker, message", [
    (Docker(code=1, err="no bake file"), "no bake file"),
    (Docker(out="not json"), "cannot read the bake definition"),
    (Docker(out="[]"), "cannot read the bake definition: not an object"),
])
def test_a_definition_that_cannot_be_read_fails_the_screening(docker, message):
    with pytest.raises(DockerError) as raised:
        docker_bake._definition(docker, [])
    assert message in messages.with_output(raised.value)
    [reason] = docker_bake.check(docker, [], policy.Policy(os.getcwd(), rules()))
    assert reason.severity is Severity.FAILED and message in messages.with_output(reason)


def test_screen_checks_against_the_current_directory(project, monkeypatch):
    monkeypatch.chdir(project)
    docker = Docker(out=json.dumps({"target": {"app": {"context": "/etc"}}}))

    [reason] = docker_bake.check(docker, [], policy.Policy(os.getcwd(), rules()))
    assert reason == "target app: context '/etc' is outside " + str(project)
    assert reason.severity is Severity.REFUSED


@pytest.mark.parametrize("argv, args", [
    (["buildx", "bake", "app"], ["app"]),
    (["buildx", "--builder", "b", "bake", "-f", "x.hcl"], ["-f", "x.hcl"]),
    (["buildx", "build", "."], None),
    (["buildx", "bake"], []),
    (["build", "."], None),
    (["run", "bake"], None),
])
def test_bake_arguments_are_taken_from_buildx_bake_only(argv, args):
    assert docker_cli.DockerCommand(argv, runtime=None)._bake_arguments() == args


@pytest.mark.parametrize("docker, code", [
    (Docker(out=json.dumps({"target": {}})), None),                              # passes: docker runs it
    (Docker(out=json.dumps({"target": {"app": {"context": "/etc"}}})), 1),     # refused
    (Docker(code=1, err="no bake file"), 1),                                    # cannot be screened
])
def test_bake_runs_only_when_screening_passes(docker, code):
    assert docker_cli._dispatch(["buildx", "bake", "app"], make_runtime(docker=docker)) == code
    assert docker.executed == ([["buildx", "bake", "app"]] if code is None else [])


def test_bake_print_is_not_screened():
    docker = Docker(code=1)  # screening would fail

    docker_cli._dispatch(["buildx", "bake", "--print"], make_runtime(docker=docker))

    assert docker.commands == [] and docker.executed == [["buildx", "bake", "--print"]]
