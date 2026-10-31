import os
import subprocess

import pytest
from fakes import make_runtime

from dockscreen import ids
from dockscreen.compose import compose_cli
from dockscreen.dockerclient import Docker


def test_exported_names_the_ids():
    assert ids.exported((1000, 1001)) == {"UID": "1000", "GID": "1001"}


def test_main_passes_the_callers_ids_to_compose_without_changing_its_own_environment(monkeypatch, tmp_path):
    seen = []

    def run(cmd, **kwargs):
        seen.append(kwargs.get("env"))
        return subprocess.CompletedProcess(cmd, 1, "", "stop here")

    (tmp_path / "compose.yaml").write_text("")
    monkeypatch.setenv("UID", "7")

    compose_cli.main(["build"], make_runtime(docker=Docker.new_for_testing(run), cwd=str(tmp_path)))

    # a pre-set UID is overridden: the shell cannot make ${UID} mean someone else
    assert seen[0]["UID"] == "4242" and seen[0]["GID"] == "4343"  # fakes.ME
    assert seen[0]["PATH"] == os.environ["PATH"]
    assert os.environ["UID"] == "7"


@pytest.mark.parametrize("spec, expected", [
    ("1000:1000", (1000, 1000)),
    ("0:0", (0, 0)),
    ("1000", None),     # a uid alone leaves the group to the image
    ("alice:1", None),  # names are not ids
    ("1:", None),
    ("١:1", None),      # Unicode digits are not ids
    ("-1:1", None),
])
def test_parse_user(spec, expected):
    assert ids.parse_user(spec) == expected


def test_parse_id():
    assert ids.parse_id(42) == 42
    assert ids.parse_id("42") == 42
    assert ids.parse_id("x") is None


def test_format_user():
    assert ids.format_user((1, 2)) == "1:2"
