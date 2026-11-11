import pytest

from dockscreen.host.docker import DockerError
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding, Verdict
from dockscreen.util import messages


def test_a_finding_reads_as_its_subject_and_text():
    found = Finding("user '0:0': uid 0 is root", subject="service web", help="set user:")

    assert str(found) == "service web: user '0:0': uid 0 is root"
    assert (found.subject, found.text, found.help) == ("service web", "user '0:0': uid 0 is root",
                                                       "set user:")
    assert found.verdict is Verdict.REFUSED and found.mark is messages.BAD
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

    found = Finding.of(reason, Verdict.FAILED, "container abc")

    assert str(found) == "container abc: docker ps failed"
    assert (found.help, messages.output_of(found), found.verdict) == (
        "is docker running?", "connection refused", Verdict.FAILED)


def test_with_text_and_with_help_keep_the_rest_of_a_finding_and_its_docker_error():
    plain = Finding("text", Verdict.REFUSED, "service web", "help")
    printed = Finding("text", Verdict.FAILED, "service web", "help", DockerError("text", "docker said"))

    for found in (plain, printed):
        changed = found.with_help("other help")
        assert (changed.text, changed.subject, changed.verdict) == ("text", "service web", found.verdict)
        assert changed.help == "other help"
        assert found.with_text("other").help == "help"
        retexted = found.with_text("other")
        assert (retexted.text, retexted.verdict) == ("other", found.verdict)
    assert messages.output_of(plain.with_help("x")) is None
    # the docker error stays with the copy
    assert messages.output_of(printed.with_text("other")) == "docker said"
    assert messages.output_of(printed.with_help("x")) == "docker said"
    assert printed.with_help(None).help is None


def test_failure_of_an_error_keeps_what_docker_printed():
    failure = finding.failure_of(DockerError("docker ps failed", "daemon down"), "container abc")

    assert str(failure) == "container abc: docker ps failed"
    assert (messages.output_of(failure), failure.verdict) == ("daemon down", Verdict.FAILED)
    assert messages.output_of(finding.failure_of(ValueError("bad"))) is None


def test_of_a_finding_keeps_its_subject_in_the_text():
    inner = Finding("uid 0 is root", subject="hook")

    assert str(Finding.of(inner, subject="service web")) == "service web: hook: uid 0 is root"


def test_refused_and_failed_make_findings_about_one_subject():
    assert [(str(f), f.verdict) for f in finding.refusals(["a", "b"], "volume v")] == [
        ("volume v: a", Verdict.REFUSED), ("volume v: b", Verdict.REFUSED)]
    assert [f.verdict for f in finding.failures(["a"])] == [Verdict.FAILED]


def test_failure_of_an_error_says_what_to_do_if_told():
    failure = finding.failure_of(DockerError("bake --print failed", "no file"), help="fix the bake files")
    assert (failure.help, messages.output_of(failure)) == ("fix the bake files", "no file")
