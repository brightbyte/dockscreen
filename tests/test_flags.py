import pytest
from fakes import FakeDocker, compose_project, make_runtime

from dockscreen import docker_cli, flags
from dockscreen.compose import compose_cli

PROJECT = {"name": "proj", "services": {"web": {"image": "x:1", "user": "65534:65534"}}}

FLAG = "--skip-screening"


@pytest.mark.parametrize("argv, found, rest", [
    ([FLAG, "up"], True, ["up"]),
    (["-f", "a.yml", FLAG, "up", "-d"], True, ["-f", "a.yml", "up", "-d"]),
    ([FLAG, "--dry-run", FLAG, "ps"], True, ["--dry-run", "ps"]),
    (["up", FLAG], False, ["up", FLAG]),               # after the subcommand: not ours, docker rejects it
    (["run", "img", FLAG], False, ["run", "img", FLAG]),
    (["-f", FLAG, "up"], False, ["-f", FLAG, "up"]),   # a value, not the flag
    (["--", FLAG], False, ["--", FLAG]),
    ([], False, []),
])
def test_only_a_global_option_counts(argv, found, rest):
    line = flags.CommandLine(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE, {FLAG})
    assert (line.skip_screening, line.argv) == (found, rest)


def test_options_given_before_count_with_the_ones_taken_out():
    line = flags.CommandLine(["--helpful", "up"], compose_cli.GLOBAL_OPTS_WITH_VALUE, compose_cli.OWN_OPTIONS,
                             given={flags.ALLOW_ME})
    assert line.allow_me and line.helpful and not line.skip_screening
    assert (line.argv, line.sub, line.global_args, line.args) == (["up"], "up", [], [])


def test_banner_goes_to_stderr(capsys):
    flags.banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "screening is disabled" in captured.err and "no defaults are added" in captured.err


def test_dockscreen_with_the_flag_is_plain_compose_with_a_warning(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, PROJECT)

    compose_cli.main([FLAG, "up", "-d"], runtime, ())

    assert runtime.docker.forwarded == [["up", "-d"]] and recorder.captured == []  # not inspected
    assert "screening is disabled" in capsys.readouterr().err


def test_dockscreen_flag_also_skips_the_extra_subcommands(tmp_path):
    runtime, recorder = compose_project(tmp_path, PROJECT)
    compose_cli.main([FLAG, "audit"], runtime, ())
    assert runtime.docker.forwarded == [["audit"]] and recorder.captured == []  # nothing of ours runs


@pytest.mark.parametrize("argv, expected", [
    ([FLAG, "run", "--privileged", "img"], ["run", "--privileged", "img"]),
    ([FLAG, "compose", "up"], ["compose", "up"]),
    (["-H", "tcp://x", FLAG, "create", "img"], ["-H", "tcp://x", "create", "img"]),
])
def test_docker_with_the_flag_is_plain_docker_with_a_warning(capsys, argv, expected):
    docker = FakeDocker()

    docker_cli._dispatch(argv, make_runtime(docker=docker))

    assert docker.executed == [expected] and docker.calls == []  # no defaults added, no gate, no dockscreen
    assert "screening is disabled" in capsys.readouterr().err


def test_docker_without_a_global_flag_gets_no_exemption():
    docker = FakeDocker()
    docker_cli._dispatch(["create", "img", FLAG], make_runtime(docker=docker))  # belongs to the command
    assert docker.executed == [
        ["create", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "img", FLAG]]


@pytest.mark.parametrize("argv", [["--helpful", "up"], ["--verbose", "up"], ["--verbose", "--helpful", "up"]])
def test_helpful_and_verbose_are_ours_and_not_passed_on(argv):
    line = flags.CommandLine(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE, compose_cli.OWN_OPTIONS)
    assert (line.helpful, line.argv) == (True, ["up"])


def test_verbose_after_the_subcommand_is_dockers_own():
    line = flags.CommandLine(["up", "--verbose"], compose_cli.GLOBAL_OPTS_WITH_VALUE, compose_cli.OWN_OPTIONS)
    assert (line.helpful, line.argv) == (False, ["up", "--verbose"])


@pytest.mark.parametrize("argv, helpful", [
    (["--helpful", "ps"], True), (["--verbose", "ps"], True), (["ps"], False), (["audit", "img"], True)])
def test_the_helpful_mode_follows_the_flags_and_the_audit_command(argv, helpful):
    from dockscreen import messages

    docker_cli._dispatch(argv, make_runtime(docker=FakeDocker(image_user="app")))

    assert messages._helpful is helpful


def test_compose_audit_is_helpful(tmp_path):
    from dockscreen import messages
    runtime, _ = compose_project(tmp_path, PROJECT)

    compose_cli.main(["audit"], runtime, ())
    assert messages._helpful is True
    compose_cli.main(["--verbose", "ps"], runtime, ())
    assert messages._helpful is True and runtime.docker.forwarded == [["ps"]]  # --verbose stays ours
