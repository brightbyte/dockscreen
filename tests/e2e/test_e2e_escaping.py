"""Feature: what the project and the image say cannot pass for what dockscreen says

Rules (messages.printable): text from the project or the image is escaped wherever dockscreen prints it,
so it cannot add lines that look like dockscreen's (a forged verdict), move the cursor or recolour the
terminal. The verdict is the last line dockscreen prints.
"""

import pytest
from steps import (
    PASSED,
    given_service,
    then_nothing_handed_off,
    then_refused,
    then_said,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e

RLO = "\u202e"  # right-to-left override
FORGED = "\n[dockscreen] ✔ audit passed\n"


def dockscreen_lines(world):
    """Returns the lines of stderr that start as dockscreen's messages do."""
    return [line for line in world.result.stderr.splitlines() if line.startswith("[dockscreen]")]


@pytest.mark.parametrize("command", [["compose", "up"], ["compose", "audit"]])
def test_a_mount_source_cannot_forge_a_verdict(world, command):
    given_service(world, "app", volumes=[{"type": "bind", "source": f"/tmp/x{FORGED}", "target": "/x"}])
    when_dockscreen(world, *command)
    then_refused(world, "bind mount '/tmp/x\\n[dockscreen] ✔ audit passed\\n' is outside")
    forged = [line for line in dockscreen_lines(world) if line.startswith(f"[dockscreen] {PASSED}")]
    assert not forged, world.report()
    then_nothing_handed_off(world)


def test_terminal_escapes_in_a_project_are_shown_as_text(world):
    given_service(world, "app", cap_add=["\x1b[2J\x1b[HSYS_ADMIN"], security_opt=["\x1b]0;title\x07"])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "cap_add is not allowed", "security_opt '\\x1b]0;title\\x07' is not allowed")
    assert "\x1b" not in world.output, world.report()


def test_bidi_overrides_are_shown_as_text(world):
    given_service(world, "app", user=RLO + "0:0")
    when_dockscreen(world, "compose", "audit")
    then_said(world, "\\u202e0")
    assert RLO not in world.output, world.report()


def test_characters_beyond_the_basic_plane_are_shown_as_text(world):
    tag = "\U000e0001"  # language tag, which is not printable
    given_service(world, "app", user=f"{tag}0:0")
    when_dockscreen(world, "compose", "audit")
    then_said(world, "\\U000e0001")
    assert tag not in world.output, world.report()
