import pytest

from dockscreen.screen import imagedecision

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


@pytest.mark.parametrize("kind, refused, pins_user, replaces_image_user", [
    (imagedecision.Kind.EXPLICIT, False, False, False),   # the command line's user runs as given
    (imagedecision.Kind.CONFIGURED, False, True, True),
    (imagedecision.Kind.OK, False, True, False),           # the image's own user, pinned as numbers
    (imagedecision.Kind.FALLBACK, False, True, True),
    (imagedecision.Kind.REFUSED, True, False, False),
    (imagedecision.Kind.FAILED, True, False, False),       # must not run either: nothing was checked
])
def test_assessment_predicates(kind, refused, pins_user, replaces_image_user):
    assessment = imagedecision.Assessment(kind, [])
    assert (assessment.refused, assessment.pins_user, assessment.replaces_image_user) == (
        refused, pins_user, replaces_image_user)
