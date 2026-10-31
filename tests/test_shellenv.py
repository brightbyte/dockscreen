import os
import subprocess

import pytest
from fakes import make_runtime

from dockscreen import messages
from dockscreen.compose import compose_cli, shellenv
from dockscreen.dockerclient import Docker


def config(**services):
    return {"name": "p", "services": {name: {"environment": env} for name, env in services.items()}}


def test_variables_that_are_the_shells_own_are_listed_per_service_without_their_values():
    shell = {"TOKEN": "s3cret", "HOME": "/home/me", "UID": "1000"}
    cfg = config(web={"TOKEN": "s3cret", "OWN": "x", "UID": "1000"}, db={"HOME": "/home/me"}, job={"A": "b"})

    assert shellenv._copied(cfg, shell) == {"web": ["TOKEN"], "db": ["HOME"]}
    lines = shellenv.describe(cfg, shell)
    assert lines == [
        messages.Marked(messages.WARN, "service db: environment variables taken from your shell: HOME"),
        messages.Marked(messages.WARN, "service web: environment variables taken from your shell: TOKEN")]
    assert all("s3cret" not in line for line in lines)


@pytest.mark.parametrize("environment, shell", [
    ({"A": "explicit"}, {"A": "other"}),
    ({"A": "x"}, {}),
    ({"A": None}, {"A": "shell"}),
    ({"A": ""}, {"A": ""}),
    ({"B": "secret"}, {"A": "secret"}),   # interpolated under another name: not recognised
    ({"UID": "1000"}, {"UID": "1000"}),   # dockscreen's own export
])
def test_nothing_is_reported_for_these(environment, shell):
    assert shellenv._copied(config(web=environment), shell) == {}


def test_services_without_an_environment_are_fine():
    assert shellenv._copied({"services": {"web": {}, "db": None}}, {"A": "b"}) == {}


def test_exported_names_the_ids():
    assert shellenv.exported((1000, 1001)) == {"UID": "1000", "GID": "1001"}


def test_main_passes_the_callers_ids_to_compose_without_changing_its_own_environment(monkeypatch, tmp_path):
    seen = []

    def run(cmd, **kwargs):
        seen.append(kwargs.get("env"))
        return subprocess.CompletedProcess(cmd, 1, "", "stop here")

    (tmp_path / "compose.yaml").write_text("")
    monkeypatch.setenv("UID", "7")

    compose_cli.main(["build"], make_runtime(docker=Docker.new_for_testing(run), cwd=str(tmp_path)), ())

    # a pre-set UID is overridden: the shell cannot make ${UID} mean someone else
    assert seen[0]["UID"] == "4242" and seen[0]["GID"] == "4343"  # fakes.ME
    assert seen[0]["PATH"] == os.environ["PATH"]
    assert os.environ["UID"] == "7"
