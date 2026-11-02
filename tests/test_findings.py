import pytest

from dockscreen.host.dockerclient import DockerError
from dockscreen.screen import findings
from dockscreen.screen.findings import Finding, Report, Severity, Verdict


def test_exit_statuses_leave_two_for_usage_errors():
    assert [int(v) for v in Verdict] == [0, 1, 3]


def test_a_finding_reads_as_its_subject_and_text():
    finding = Finding("user '0:0': uid 0 is root", subject="service web", help="set user:")

    assert finding == "service web: user '0:0': uid 0 is root"
    assert (finding.subject, finding.text, finding.help) == ("service web", "user '0:0': uid 0 is root",
                                                             "set user:")
    assert finding.severity is Severity.REFUSED and finding.fatal
    assert Finding("no subject") == "no subject"


def test_of_keeps_what_a_finding_says_beyond_its_text():
    reason = Finding("docker ps failed", help="is docker running?", output="connection refused")

    finding = Finding.of(reason, Severity.FAILED, "container abc")

    assert finding == "container abc: docker ps failed"
    assert (finding.help, finding.output, finding.severity) == (
        "is docker running?", "connection refused", Severity.FAILED)


def test_failure_of_an_error_keeps_what_docker_printed():
    failure = findings.failure_of(DockerError("docker ps failed", "daemon down"), "container abc")

    assert failure == "container abc: docker ps failed"
    assert (failure.output, failure.severity) == ("daemon down", Severity.FAILED)
    assert findings.failure_of(ValueError("bad")).output is None


def test_of_a_finding_keeps_its_subject_in_the_text():
    inner = Finding("uid 0 is root", subject="hook")

    assert Finding.of(inner, subject="service web") == "service web: hook: uid 0 is root"


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


def test_refused_and_failed_make_findings_about_one_subject():
    assert [(f, f.severity) for f in findings.refused(["a", "b"], "volume v")] == [
        ("volume v: a", Severity.REFUSED), ("volume v: b", Severity.REFUSED)]
    assert [f.severity for f in findings.failed(["a"])] == [Severity.FAILED]


def test_failure_of_an_error_says_what_to_do_if_told():
    failure = findings.failure_of(DockerError("bake --print failed", "no file"), help="fix the bake files")
    assert (failure.help, failure.output) == ("fix the bake files", "no file")
