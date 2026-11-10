from dockscreen.model.image import Image
from dockscreen.model.origin import Origin
from dockscreen.screen import amendments, hardening
from dockscreen.screen.amendments import Amendment
from dockscreen.screen.notices import NoticeSeverity
from dockscreen.screen.userdecision import UserDecision


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
    pinned = amendments.pinned_user(decision, "img")
    assert pinned.args == ("--user=7:8",)
    assert (str(pinned.notice), pinned.notice.severity) == (
        "image img runs as 7:8, passed to docker as numbers", NoticeSeverity.INFO)


def test_the_default_user_instead_of_root_is_a_warning_that_names_its_home():
    decision = UserDecision(Origin.DOCKSCREEN, Image("img"), user=(9, 9), home="/tmp", replaces_root=True)
    pinned = amendments.pinned_user(decision, "img")
    assert pinned.args == ("--user=9:9",)
    assert pinned.notice.severity is NoticeSeverity.WARNING
    assert "its HOME is set to /tmp" in pinned.notice.help
