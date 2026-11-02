import pytest

from dockscreen.model.image import Image
from dockscreen.model.origin import Origin
from dockscreen.screen.assessment import Assessment
from dockscreen.screen.findings import Finding, Severity

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


IMAGE = Image("img")
REFUSAL, FAILURE, NOTE = Finding("no"), Finding("lost", Severity.FAILED), Finding("hm", Severity.NOTABLE)


@pytest.mark.parametrize("origin, root, found, refused, pins_user, replaces_image_user, accepted", [
    (Origin.COMMAND_LINE, False, (), False, False, False, False),  # the command line's user runs as given
    (Origin.DOCKSCREEN, False, (), False, False, False, False),    # so does the one dockscreen chose
    (Origin.CONFIG, False, (NOTE,), False, True, True, True),      # a note forbids nothing
    (Origin.IMAGE, False, (), False, True, False, True),           # the image's own user, as numbers
    (Origin.CONFIG, True, (), False, True, True, False),           # the default user instead of root
    (Origin.IMAGE, False, (REFUSAL,), True, False, False, False),
    (Origin.IMAGE, False, (FAILURE,), True, False, False, False),  # must not run either: nothing was checked
])
def test_assessment_predicates(origin, root, found, refused, pins_user, replaces_image_user, accepted):
    assessment = Assessment(origin, IMAGE, found, replaces_root=root)
    found = (assessment.refused, assessment.pins_user, assessment.replaces_image_user, assessment.accepted)
    assert found == (refused, pins_user, replaces_image_user, accepted)


def test_an_assessment_tells_reasons_from_notes_and_failures_from_refusals():
    assessment = Assessment(Origin.IMAGE, IMAGE, (NOTE, REFUSAL))
    assert (assessment.reasons, assessment.notes, assessment.failed) == ([REFUSAL], [NOTE], False)
    failure = Assessment.failure(IMAGE, "lost")
    assert failure.failed and failure.reasons == ["lost"] and failure.image is IMAGE
