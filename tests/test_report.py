import pytest
from fakes import marked

from dockscreen.host.dockerclient import DockerError
from dockscreen.screen.findings import Finding, Severity
from dockscreen.screen.report import Report, Verdict
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
    assert marked([found.brief]) == [line]


def test_report(capsys):
    assert Report.refusal("a").show() == 1
    assert Report.failure("b").show() == 3
    assert Report().show() == 0
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] {messages.BAD} refusing: a", "[dockscreen] ⊖ denied by audit",
        f"[dockscreen] {messages.BAD} b", "[dockscreen] ✘ audit failed",
        "[dockscreen] ✔ audit passed",
    ]

    assert Report.refusal("a").show(brief_mode=True) == 1
    assert capsys.readouterr() == ("⊖ denied by audit: a\n", "")


def test_report_shows_what_does_not_stop_the_command_before_the_reasons(capsys):
    found = Report.of([Finding("a", Severity.REFUSED), Finding("b", Severity.NOTABLE),
                       Finding("c", Severity.ROUTINE)])

    assert found.show() == 1
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] {messages.WARN} b", f"[dockscreen] {messages.ROUTINE} c",
        f"[dockscreen] {messages.BAD} refusing: a", "[dockscreen] \u2296 denied by audit",
    ]


def test_screened_tells_whether_the_command_may_run(capsys):
    assert Report.of([Finding("noted", Severity.NOTABLE)]).show_screening()
    assert not Report.refusal("a").show_screening()


def test_exit_statuses_leave_two_for_usage_errors():
    assert [int(v) for v in Verdict] == [0, 1, 3]


@pytest.mark.parametrize("severities, outcome", [
    ([], Verdict.PASSED),
    ([Severity.ROUTINE, Severity.NOTABLE], Verdict.PASSED),
    ([Severity.NOTABLE, Severity.REFUSED], Verdict.REFUSED),
    ([Severity.REFUSED, Severity.FAILED], Verdict.FAILED),  # it could not look at everything
])
def test_the_verdict_follows_from_the_worst_finding(severities, outcome):
    found = Report.of(Finding(s.value, s) for s in severities)

    assert found.verdict is outcome
    assert found.passed == (outcome is Verdict.PASSED)
    assert found.reasons == [f for f in found.findings if f.severity in (Severity.REFUSED, Severity.FAILED)]


def test_with_more_findings_appends_to_the_findings_of_the_report():
    first, second = Finding("a", Severity.NOTABLE), Finding("b")

    found = Report.of([first]).with_more_findings([second])

    assert found.findings == (first, second)
    assert found.verdict is Verdict.REFUSED
