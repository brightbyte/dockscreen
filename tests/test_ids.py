import os

import pytest

from fakes import runtime

from dockscreen import ids
from dockscreen.compose import compose_cli


def test_exported_names_the_ids():
    assert ids.exported((1000, 1001)) == {"UID": "1000", "GID": "1001"}


def test_main_passes_the_real_ids_to_compose_without_changing_its_own_environment(monkeypatch):
    seen = []
    monkeypatch.setattr(compose_cli, "_forward", lambda argv, runtime: seen.append(runtime.docker.env))
    monkeypatch.setenv("UID", "7")

    compose_cli.main(["ps"], runtime())

    # a pre-set UID is overridden: the shell cannot make ${UID} mean someone else
    assert seen[0]["UID"] == str(os.getuid()) and seen[0]["GID"] == str(os.getgid())
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
