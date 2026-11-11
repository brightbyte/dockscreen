import pytest

from dockscreen.model.image import Image
from dockscreen.model.origin import Origin
from dockscreen.policy.finding import Finding, Verdict
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.userdecision import UserDecision

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


IMAGE = Image("img")
REFUSAL, FAILURE = Finding("no"), Finding("lost", Verdict.FAILED)
NOTE = Notice("hm", NoticeSeverity.WARNING)


@pytest.mark.parametrize("origin, root, user, notices, findings, refused, pins_user, accepted", [
    (Origin.COMMAND_LINE, False, None, (), (), False, False, False),  # the command line's user runs as given
    (Origin.CONFIG, False, (7, 7), (NOTE,), (), False, True, True),   # a note forbids nothing
    (Origin.IMAGE, False, (7, 7), (), (), False, True, True),         # the image's own user, as numbers
    (Origin.DOCKSCREEN, True, (9, 9), (), (), False, True, False),    # the default user instead of root
    (Origin.IMAGE, False, (7, 7), (), (REFUSAL,), True, False, False),
    (None, False, None, (), (FAILURE,), True, False, False),  # must not run either: nothing was checked
])
def test_decision_predicates(origin, root, user, notices, findings, refused, pins_user, accepted):
    decision = UserDecision(origin, IMAGE, notices, findings, user=user, replaces_root=root)
    assert (decision.refused, decision.pins_user, decision.accepted) == (refused, pins_user, accepted)


def test_a_decision_tells_failures_from_refusals():
    decision = UserDecision(Origin.IMAGE, IMAGE, (NOTE,), (REFUSAL,))
    assert (decision.findings, decision.notices, decision.failed) == ((REFUSAL,), (NOTE,), False)
    failure = UserDecision.failure(IMAGE, "lost")
    assert failure.failed and failure.image is IMAGE
    assert failure.findings == (Finding("lost", Verdict.FAILED),)
    assert failure.origin is None  # it has no user to come from anywhere
