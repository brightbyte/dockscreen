import pytest

from dockscreen.model.image import Image
from dockscreen.screen.assessment import Assessment, Kind
from dockscreen.screen.findings import Finding, Severity

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


IMAGE = Image("img")
REFUSAL, FAILURE, NOTE = Finding("no"), Finding("lost", Severity.FAILED), Finding("hm", Severity.NOTABLE)


@pytest.mark.parametrize("kind, found, refused, pins_user, replaces_image_user", [
    (Kind.EXPLICIT, (), False, False, False),       # the command line's user runs as given
    (Kind.CONFIGURED, (NOTE,), False, True, True),  # a note forbids nothing
    (Kind.IMAGE, (), False, True, False),           # the image's own user, pinned as numbers
    (Kind.FALLBACK, (), False, True, True),
    (Kind.IMAGE, (REFUSAL,), True, False, False),
    (Kind.IMAGE, (FAILURE,), True, False, False),   # must not run either: nothing was checked
])
def test_assessment_predicates(kind, found, refused, pins_user, replaces_image_user):
    assessment = Assessment(kind, IMAGE, found)
    assert (assessment.refused, assessment.pins_user, assessment.replaces_image_user) == (
        refused, pins_user, replaces_image_user)


def test_an_assessment_tells_reasons_from_notes_and_failures_from_refusals():
    assessment = Assessment(Kind.IMAGE, IMAGE, (NOTE, REFUSAL))
    assert (assessment.reasons, assessment.notes, assessment.failed) == ([REFUSAL], [NOTE], False)
    failure = Assessment.failure(IMAGE, "lost")
    assert failure.failed and failure.reasons == ["lost"] and failure.image is IMAGE
