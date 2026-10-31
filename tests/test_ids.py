import pytest

from dockscreen import ids


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
