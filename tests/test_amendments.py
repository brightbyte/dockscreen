from fakes import id_facts

from dockscreen.model.image import Image
from dockscreen.model.origin import Origin
from dockscreen.screen import amendments, hardening
from dockscreen.screen.amendments import Amendment
from dockscreen.screen.notices import NoticeSeverity
from dockscreen.screen.policy import Policy
from dockscreen.screen.userdecision import UserDecision

POLICY = Policy(id_facts())


def test_the_arguments_go_before_the_command_lines_own_in_order():
    found = [Amendment(("--cap-drop=ALL",)), Amendment(("-e", "HOME=/tmp"))]
    assert amendments.applied(["-i", "img"], found) == ["--cap-drop=ALL", "-e", "HOME=/tmp", "-i", "img"]


def test_the_defaults_of_a_container_are_reported_with_how_to_override_them():
    defaults = hardening.container_defaults()
    assert defaults.args == ("--cap-drop=ALL", "--security-opt=no-new-privileges:true")
    assert str(defaults.notice) == "added --cap-drop=ALL --security-opt=no-new-privileges:true"
    assert "--cap-add" in defaults.notice.help


def test_a_pinned_user_is_passed_as_numbers():
    decision = UserDecision(Origin.IMAGE, Image("img"), user=(7, 8))
    [pinned] = POLICY.user_amendments(decision, "img")
    assert pinned.args == ("--user=7:8",)
    assert (str(pinned.notice), pinned.notice.severity) == (
        "image img runs as 7:8, passed to docker as numbers", NoticeSeverity.INFO)


def test_the_default_user_instead_of_root_gets_its_home_and_one_warning():
    decision = UserDecision(Origin.DOCKSCREEN, Image("img"), user=(9, 9), home="/tmp", replaces_root=True)
    found = POLICY.user_amendments(decision, "img")
    assert amendments.applied([], found) == ["--user=9:9", "-e", "HOME=/tmp"]
    [warning] = amendments.notices(found)
    assert warning.severity is NoticeSeverity.WARNING
    assert "its HOME is set to /tmp" in warning.help


def test_without_a_home_the_default_user_gets_none():
    decision = UserDecision(Origin.DOCKSCREEN, Image("img"), user=(9, 9), home="", replaces_root=True)
    found = POLICY.user_amendments(decision, "img")
    assert amendments.applied([], found) == ["--user=9:9"]
    assert "HOME" not in amendments.notices(found)[0].help
