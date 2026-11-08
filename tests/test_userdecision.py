import pytest

from dockscreen.model.image import Image
from dockscreen.model.origin import Origin
from dockscreen.screen.userdecision import UserDecision
from dockscreen.screen.findings import Finding, Severity

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


IMAGE = Image("img")
REFUSAL, FAILURE, NOTE = Finding("no"), Finding("lost", Severity.FAILED), Finding("hm", Severity.NOTABLE)


@pytest.mark.parametrize("origin, root, user, found, refused, pins_user, accepted", [
    (Origin.COMMAND_LINE, False, None, (), False, False, False),  # the command line's user runs as given
    (Origin.CONFIG, False, (7, 7), (NOTE,), False, True, True),   # a note forbids nothing
    (Origin.IMAGE, False, (7, 7), (), False, True, True),         # the image's own user, as numbers
    (Origin.DOCKSCREEN, True, (9, 9), (), False, True, False),    # the default user instead of root
    (Origin.IMAGE, False, (7, 7), (REFUSAL,), True, False, False),
    (None, False, None, (FAILURE,), True, False, False),          # must not run either: nothing was checked
])
def test_decision_predicates(origin, root, user, found, refused, pins_user, accepted):
    decision = UserDecision(origin, IMAGE, found, user=user, replaces_root=root)
    assert (decision.refused, decision.pins_user, decision.accepted) == (refused, pins_user, accepted)


def test_an_decision_tells_reasons_from_notes_and_failures_from_refusals():
    decision = UserDecision(Origin.IMAGE, IMAGE, (NOTE, REFUSAL))
    assert (decision.reasons, decision.notes, decision.failed) == ([REFUSAL], [NOTE], False)
    failure = UserDecision.failure(IMAGE, "lost")
    assert failure.failed and failure.reasons == ["lost"] and failure.image is IMAGE
    assert failure.origin is None  # it has no user to come from anywhere
