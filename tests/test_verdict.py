import pytest
from fakes import marked

from dockscreen.host.dockerclient import DockerError
from dockscreen.screen import verdict
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.util import messages


@pytest.mark.parametrize("found, line", [
    (Report(), "✔ audit passed"),
    (Report.refusal("a"), "⊖ denied by audit: a"),
    (Report.of(Finding(r) for r in "abc"), "⊖ denied by audit: a (+2 more)"),
    (Report.failure("no\nimage"), "✘ audit failed: no\\x0aimage"),  # still one line
    (Report.failure(DockerError("docker ps failed", "a\nb")),
     "✘ audit failed: docker ps failed: a\\x0ab"),  # the output too
    # what stops the command comes first in the line, whatever was reported before it
    (Report.of([Finding("fine", Severity.ROUTINE), Finding("a")]), "⊖ denied by audit: a"),
])
def test_brief(found, line):
    assert marked([verdict.brief(found)]) == [line]


def test_report(capsys):
    assert verdict.report(Report.refusal("a")) == 1
    assert verdict.report(Report.failure("b")) == 3
    assert verdict.report(Report()) == 0
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] {messages.BAD} refusing: a", "[dockscreen] ⊖ denied by audit",
        f"[dockscreen] {messages.BAD} b", "[dockscreen] ✘ audit failed",
        "[dockscreen] ✔ audit passed",
    ]

    assert verdict.report(Report.refusal("a"), brief_mode=True) == 1
    assert capsys.readouterr() == ("⊖ denied by audit: a\n", "")


def test_report_shows_what_does_not_stop_the_command_before_the_reasons(capsys):
    found = Report.of([Finding("a", Severity.REFUSED), Finding("b", Severity.NOTABLE),
                       Finding("c", Severity.ROUTINE)])

    assert verdict.report(found) == 1
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] {messages.WARN} b", f"[dockscreen] {messages.ROUTINE} c",
        f"[dockscreen] {messages.BAD} refusing: a", "[dockscreen] \u2296 denied by audit",
    ]


def test_screened_tells_whether_the_command_may_run(capsys):
    assert verdict.screened(Report.of([Finding("noted", Severity.NOTABLE)]))
    assert not verdict.screened(Report.refusal("a"))
