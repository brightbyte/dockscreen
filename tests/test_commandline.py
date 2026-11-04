import pytest
from fakes import FakeDocker, compose_line, compose_project, docker_dispatch, docker_line, make_runtime

from dockscreen.commands import docker_compose
from dockscreen.util import commandline

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
    line = commandline.main_commandline(argv, docker_compose.GLOBAL_OPTS_WITH_VALUE, {FLAG})
    assert (line.skip_screening, line.argv) == (found, rest)


@pytest.mark.parametrize("argv, split", [
    (["-f", "a.yml", "up", "-d"], (("-f", "a.yml"), "up", ("-d",))),
    (["--dry-run", "ps"], (("--dry-run",), "ps", ())),
    (["-f", "a.yml"], (("-f", "a.yml"), None, ())),
    ([], ((), None, ())),
])
def test_a_command_line_is_split_at_its_command(argv, split):
    line = commandline.main_commandline(argv, docker_compose.GLOBAL_OPTS_WITH_VALUE)
    assert (line.lead_args, line.cmd, line.args) == split


def test_a_subcommand_keeps_the_options_given_before_it_and_knows_what_came_before():
    line = docker_line("--allow-me", "-H", "unix:///s", "compose", "--helpful", "-f", "a.yml", "up", "-d")
    compose = line.subcommand(docker_compose.GLOBAL_OPTS_WITH_VALUE, docker_compose.OWN_OPTIONS)
    assert compose.allow_me and compose.helpful and not compose.skip_screening
    assert (compose.lead_args, compose.cmd, compose.args) == (("-f", "a.yml"), "up", ("-d",))
    assert compose.full_argv == ["-H", "unix:///s", "compose", "-f", "a.yml", "up", "-d"]
    assert compose.global_args == ["-H", "unix:///s", "compose", "-f", "a.yml"]


def test_a_subcommand_that_inherits_the_lead_takes_the_place_of_its_command():
    line = docker_line("--allow-me", "-H", "unix:///s", "container", "run", "-it", "x")
    run = line.subcommand(inherit_lead=True)
    assert run.allow_me
    assert (run.lead_args, run.cmd, run.args, run.prefix) == (("-H", "unix:///s"), "run", ("-it", "x"), ())
    assert run.full_argv == ["-H", "unix:///s", "run", "-it", "x"]


def test_banner_goes_to_stderr(capsys):
    commandline.banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "screening is disabled" in captured.err and "no defaults are added" in captured.err


def test_dockscreen_with_the_flag_is_plain_compose_with_a_warning(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, PROJECT)

    docker_dispatch(["compose", FLAG, "up", "-d"], runtime)

    assert runtime.docker.forwarded == [["up", "-d"]] and recorder.captured == []  # not inspected
    assert "screening is disabled" in capsys.readouterr().err


def test_dockscreen_flag_also_skips_the_extra_subcommands(tmp_path):
    runtime, recorder = compose_project(tmp_path, PROJECT)
    docker_dispatch(["compose", FLAG, "audit"], runtime)
    assert runtime.docker.forwarded == [["audit"]] and recorder.captured == []  # nothing of ours runs


@pytest.mark.parametrize("argv, expected", [
    ([FLAG, "run", "--privileged", "img"], ["run", "--privileged", "img"]),
    ([FLAG, "compose", "up"], ["compose", "up"]),
    (["-H", "tcp://x", FLAG, "create", "img"], ["-H", "tcp://x", "create", "img"]),
])
def test_docker_with_the_flag_is_plain_docker_with_a_warning(capsys, argv, expected):
    docker = FakeDocker()

    docker_dispatch(argv, make_runtime(docker=docker))

    assert docker.executed == [expected] and docker.calls == []  # no defaults added, no gate, no dockscreen
    assert "screening is disabled" in capsys.readouterr().err


def test_docker_without_a_global_flag_gets_no_exemption():
    docker = FakeDocker()
    docker_dispatch(["create", "img", FLAG], make_runtime(docker=docker))  # belongs to the command
    assert docker.executed == [
        ["create", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "img", FLAG]]


@pytest.mark.parametrize("argv", [["--helpful", "up"], ["--verbose", "up"], ["--verbose", "--helpful", "up"]])
def test_helpful_and_verbose_are_ours_and_not_passed_on(argv):
    line = compose_line(*argv)
    assert (line.helpful, line.argv) == (True, ["up"])


def test_verbose_after_the_subcommand_is_dockers_own():
    line = compose_line("up", "--verbose")
    assert (line.helpful, line.argv) == (False, ["up", "--verbose"])


@pytest.mark.parametrize("argv, helpful", [
    (["--helpful", "ps"], True), (["--verbose", "ps"], True), (["ps"], False), (["audit", "img"], True)])
def test_the_helpful_mode_follows_the_flags_and_the_audit_command(argv, helpful):
    from dockscreen.util import messages

    docker_dispatch(argv, make_runtime(docker=FakeDocker(image_user="app")))

    assert messages._helpful is helpful


def test_compose_audit_is_helpful(tmp_path):
    from dockscreen.util import messages
    runtime, _ = compose_project(tmp_path, PROJECT)

    docker_dispatch(["compose", "audit"], runtime)
    assert messages._helpful is True
    docker_dispatch(["compose", "--verbose", "ps"], runtime)
    assert messages._helpful is True and runtime.docker.forwarded == [["ps"]]  # --verbose stays ours


# --- scanning helpers ------------------------------------------------------

@pytest.mark.parametrize("args, values", [
    (["-f", "a.yml", "--file", "b.yml"], ["a.yml", "b.yml"]),
    (["--file=a.yml", "-fb.yml"], ["a.yml", "b.yml"]),
    (["-f=sub/a.yml"], ["sub/a.yml"]),  # as compose reads it, not "=sub/a.yml"
    (["--files", "x", "-f"], []),  # another option, and -f without a value
    ([], []),
])
def test_option_values(args, values):
    assert commandline.option_values(args, "--file", "-f") == values


@pytest.mark.parametrize("args, value", [
    (["--pull", "always", "web"], "always"),
    (["--pull=never"], "never"),
    (["--", "--pull", "always"], None),  # belongs to the command
    (["--pull"], None),
])
def test_option_value(args, value):
    assert commandline.option_value(args, "--pull") == value
