import os
import subprocess

import pytest
from fakes import docker_dispatch, make_runtime

from dockscreen.host import shellenv
from dockscreen.host.dockerclient import Docker


def config(**services):
    return {"name": "p", "services": {name: {"environment": env} for name, env in services.items()}}


def test_variables_that_are_the_shells_own_are_listed_per_service_by_name():
    shell = {"TOKEN": "s3cret", "HOME": "/home/me", "UID": "1000"}
    cfg = config(web={"TOKEN": "s3cret", "OWN": "x", "UID": "1000"}, db={"HOME": "/home/me"}, job={"A": "b"})

    assert shellenv.copied(cfg, shell) == {"web": ["TOKEN"], "db": ["HOME"]}


@pytest.mark.parametrize("environment, shell", [
    ({"A": "explicit"}, {"A": "other"}),
    ({"A": "x"}, {}),
    ({"A": None}, {"A": "shell"}),
    ({"A": ""}, {"A": ""}),
    ({"B": "secret"}, {"A": "secret"}),   # interpolated under another name: not recognised
    ({"UID": "1000"}, {"UID": "1000"}),   # dockscreen's own export
])
def test_nothing_is_reported_for_these(environment, shell):
    assert shellenv.copied(config(web=environment), shell) == {}


def test_services_without_an_environment_are_fine():
    assert shellenv.copied({"services": {"web": {}, "db": None}}, {"A": "b"}) == {}


def test_exported_names_the_ids():
    assert shellenv.exported((1000, 1001)) == {"UID": "1000", "GID": "1001"}


def test_main_passes_the_callers_ids_to_compose_without_changing_its_own_environment(monkeypatch, tmp_path):
    seen = []

    def run(cmd, **kwargs):
        seen.append(kwargs.get("env"))
        return subprocess.CompletedProcess(cmd, 1, "", "stop here")

    (tmp_path / "compose.yaml").write_text("")
    monkeypatch.setenv("UID", "7")

    docker_dispatch(["compose", "build"], make_runtime(docker=Docker.new_for_testing(run), cwd=str(tmp_path)))

    # a pre-set UID is overridden: the shell cannot make ${UID} mean someone else
    assert seen[0]["UID"] == "4242" and seen[0]["GID"] == "4343"  # fakes.ME
    assert seen[0]["PATH"] == os.environ["PATH"]
    assert os.environ["UID"] == "7"
