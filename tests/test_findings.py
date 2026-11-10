import pytest

from dockscreen.host.dockerclient import DockerError
from dockscreen.screen import findings
from dockscreen.screen.findings import Finding, Verdict
from dockscreen.util import messages


def test_a_finding_reads_as_its_subject_and_text():
    finding = Finding("user '0:0': uid 0 is root", subject="service web", help="set user:")

    assert str(finding) == "service web: user '0:0': uid 0 is root"
    assert (finding.subject, finding.text, finding.help) == ("service web", "user '0:0': uid 0 is root",
                                                             "set user:")
    assert finding.verdict is Verdict.REFUSED and finding.mark is messages.BAD
    assert str(Finding("no subject")) == "no subject"


def test_findings_are_equal_only_if_everything_they_say_is_and_cannot_be_changed():
    assert Finding("a", help="h") == Finding("a", help="h")
    assert Finding("a") != Finding("a", Verdict.FAILED)
    assert Finding("a") != Finding("a", help="h")
    assert Finding("a") != "a"
    with pytest.raises(AttributeError):
        Finding("a").text = "b"


def test_a_finding_cannot_be_a_passed_verdict():
    with pytest.raises(ValueError):
        Finding("fine", Verdict.PASSED)


def test_of_keeps_what_a_finding_says_beyond_its_text():
    reason = Finding("docker ps failed", help="is docker running?",
                     docker_error=DockerError("docker ps failed", "connection refused"))

    finding = Finding.of(reason, Verdict.FAILED, "container abc")

    assert str(finding) == "container abc: docker ps failed"
    assert (finding.help, messages.output_of(finding), finding.verdict) == (
        "is docker running?", "connection refused", Verdict.FAILED)


def test_with_text_and_with_help_keep_the_rest_of_a_finding_and_its_docker_error():
    plain = Finding("text", Verdict.REFUSED, "service web", "help")
    printed = Finding("text", Verdict.FAILED, "service web", "help", DockerError("text", "docker said"))

    for finding in (plain, printed):
        changed = finding.with_help("other help")
        assert (changed.text, changed.subject, changed.verdict) == ("text", "service web", finding.verdict)
        assert changed.help == "other help"
        assert finding.with_text("other").help == "help"
        retexted = finding.with_text("other")
        assert (retexted.text, retexted.verdict) == ("other", finding.verdict)
    assert messages.output_of(plain.with_help("x")) is None
    # the docker error stays with the copy
    assert messages.output_of(printed.with_text("other")) == "docker said"
    assert messages.output_of(printed.with_help("x")) == "docker said"
    assert printed.with_help(None).help is None


def test_failure_of_an_error_keeps_what_docker_printed():
    failure = findings.failure_of(DockerError("docker ps failed", "daemon down"), "container abc")

    assert str(failure) == "container abc: docker ps failed"
    assert (messages.output_of(failure), failure.verdict) == ("daemon down", Verdict.FAILED)
    assert messages.output_of(findings.failure_of(ValueError("bad"))) is None


def test_of_a_finding_keeps_its_subject_in_the_text():
    inner = Finding("uid 0 is root", subject="hook")

    assert str(Finding.of(inner, subject="service web")) == "service web: hook: uid 0 is root"


def test_refused_and_failed_make_findings_about_one_subject():
    assert [(str(f), f.verdict) for f in findings.refusals(["a", "b"], "volume v")] == [
        ("volume v: a", Verdict.REFUSED), ("volume v: b", Verdict.REFUSED)]
    assert [f.verdict for f in findings.failures(["a"])] == [Verdict.FAILED]


def test_failure_of_an_error_says_what_to_do_if_told():
    failure = findings.failure_of(DockerError("bake --print failed", "no file"), help="fix the bake files")
    assert (failure.help, messages.output_of(failure)) == ("fix the bake files", "no file")
