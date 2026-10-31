import pytest
from fakes import compose_project

from dockscreen import argscan
from dockscreen.compose import compose_cli


@pytest.mark.parametrize("argv, expected", [
    (["up", "-d"], 0),
    (["-f", "a.yml", "up"], 2),
    (["--file=a.yml", "up"], 1),
    (["-p", "up", "ps"], 2),  # "up" is the project name here
    (["--dry-run", "ps"], 1),
    (["--", "up"], None),
    ([], None),
    (["--help"], None),
])
def test_find_subcommand(argv, expected):
    assert argscan.find_subcommand(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE) == expected


PROJECT = {"name": "proj", "services": {"web": {"image": "x:1", "user": "65534:65534"}}}


def test_unknown_args_are_forwarded_verbatim(runtime, forwarded):
    argv = ["-f", "a.yml", "logs", "-f", "--no-such-flag", "svc"]
    compose_cli.main(argv, runtime, ())
    assert forwarded == [argv]


def test_our_own_command_gets_the_global_args_and_is_not_forwarded(tmp_path):
    runtime, recorder = compose_project(tmp_path, PROJECT)
    path = str(tmp_path / "compose.yaml")

    assert compose_cli.main(["-f", path, "audit"], runtime, ()) == 0

    assert recorder.captured[0][2:4] == ["-f", path]  # the project audited is the one -f names
    assert runtime.docker.forwarded == []


def test_our_command_name_as_an_option_value_is_not_dispatched(runtime, forwarded):
    compose_cli.main(["-p", "audit", "ps"], runtime, ())
    assert forwarded == [["-p", "audit", "ps"]]


@pytest.mark.parametrize("argv", [[], ["help"], ["--help"], ["-h"], ["-f", "a.yml", "help"]])
def test_the_overview_precedes_composes_own_help(runtime, forwarded, capsys, argv):
    compose_cli.main(argv, runtime, ())
    assert forwarded == [argv]
    out = capsys.readouterr().out
    assert out.startswith("Usage:  dockscreen compose [OPTIONS] COMMAND")
    assert "Commands dockscreen audits:" in out and "  up " in out
    assert "Commands dockscreen adds:" in out and "  harden " in out
    assert out.rstrip().endswith("Docker Compose's own help follows:")


@pytest.mark.parametrize("argv, forwarded_argv", [
    (["up", "--help"], ["up", "--help"]),
    (["up", "-h"], ["up", "-h"]),
    (["-f", "a.yml", "help", "up"], ["-f", "a.yml", "up", "--help"]),
])
def test_a_command_compose_has_gets_our_help_then_composes(runtime, forwarded, capsys, argv, forwarded_argv):
    compose_cli.main(argv, runtime, ())
    assert forwarded == [forwarded_argv]
    out = capsys.readouterr().out
    assert out.startswith("Usage:  dockscreen compose up [OPTIONS]")
    assert "dockscreen audits the project first" in out


@pytest.mark.parametrize("argv", [["help", "harden"], ["harden", "--help"], ["fix", "-h"], ["help", "fix"]])
def test_our_own_commands_get_only_our_help(runtime, forwarded, capsys, argv):
    assert compose_cli.main(argv, runtime, ()) == 0
    assert forwarded == []  # compose does not know harden
    out = capsys.readouterr().out
    assert out.startswith("Usage:  dockscreen compose harden")
    assert "Aliases:\n  dockscreen compose harden, dockscreen compose fix" in out


@pytest.mark.parametrize("argv", [["ps", "--help"], ["help", "ps"]])
def test_commands_dockscreen_leaves_alone_get_composes_help(runtime, forwarded, capsys, argv):
    compose_cli.main(argv, runtime, ())
    assert forwarded == [["ps", "--help"]]
    assert capsys.readouterr().out == ""


def test_help_after_the_service_belongs_to_its_command(tmp_path):
    runtime, recorder = compose_project(tmp_path, PROJECT)
    assert compose_cli.main(["run", "web", "grep", "--help"], runtime, ()) == 0  # screened and run, not help
    assert recorder.children[-1][-4:] == ["run", "web", "grep", "--help"]


@pytest.mark.parametrize("subcommand", sorted(compose_cli.RUNTIME_SUBCOMMANDS))
def test_runtime_subcommands_run_from_the_checked_config(tmp_path, subcommand):
    runtime, recorder = compose_project(tmp_path, PROJECT)

    compose_cli.main([subcommand, "-d"], runtime, ())

    assert "config" in recorder.captured[0]  # the project was inspected
    assert runtime.docker.forwarded == []    # the gate runs compose itself, from the hardened config


@pytest.mark.parametrize("subcommand", sorted(compose_cli.BUILD_SUBCOMMANDS))
def test_build_subcommands_get_the_build_rules_and_are_then_forwarded(tmp_path, subcommand):
    privileged = {"name": "proj", "services": {"web": {"image": "x:1", "privileged": True}}}
    runtime, _ = compose_project(tmp_path, privileged)  # refused to run, but it builds nothing wrong

    compose_cli.main([subcommand], runtime, ())

    assert runtime.docker.forwarded == [[subcommand]]


def test_build_with_problems_is_not_forwarded(tmp_path):
    outside = {"name": "proj", "services": {"web": {"image": "x:1", "build": {"context": "/etc"}}}}
    runtime, _ = compose_project(tmp_path, outside)
    assert compose_cli.main(["build"], runtime, ()) == 1
    assert runtime.docker.forwarded == []


def test_unscreened_subcommand_is_not_inspected(tmp_path):
    runtime, recorder = compose_project(tmp_path, PROJECT)
    compose_cli.main(["ps"], runtime, ())
    assert recorder.captured == [] and runtime.docker.forwarded == [["ps"]]


@pytest.mark.parametrize("argv, help_for", [
    (["up"], None),
    (["run", "app", "ls", "-h"], None),
    (["run", "app", "grep", "-h", "foo"], None),
    (["run", "app", "--help"], None),
    (["run", "-e", "--help", "app"], None),  # a flag value, not a help request
    (["up", "-d", "--help"], None),
    (["up", "-h"], "up"),
    (["up", "--help"], "up"),
    (["run", "--help"], "run"),
    (["help", "watch"], "watch"),
    (["help"], ""),
    (["ps"], None),
    (["logs", "-f"], None),
    ([], ""),
])
def test_help_request(argv, help_for):
    assert compose_cli.ComposeCommand(argv, runtime=None)._help_request() == help_for


@pytest.mark.parametrize("argv, screened", [
    (["up"], True),
    (["run", "app", "ls", "-h"], True),
    (["ps"], False),
    ([], False),
])
def test_is_screened(argv, screened):
    assert compose_cli.ComposeCommand(argv, runtime=None)._is_screened() == screened


# --- dockscreen's own options and the config file ------------------------------------

def test_allow_me_before_the_subcommand_reaches_the_checks_and_not_compose(tmp_path):
    mine = {"name": "proj", "services": {"web": {"image": "x:1", "user": "4242:4343"}}}  # fakes.ME
    runtime, recorder = compose_project(tmp_path, mine)
    assert compose_cli.main(["--allow-me", "up"], runtime, ()) == 0  # without it, your ids are refused
    assert recorder.children[-1][-1] == "up" and runtime.docker.forwarded == []


def test_as_me_before_the_subcommand_is_refused(runtime, forwarded, capsys):
    assert compose_cli.main(["--as-me", "up"], runtime, ()) == 2
    assert "--as-me goes after run or exec" in capsys.readouterr().err and forwarded == []


def test_exec_as_me_reaches_compose_as_the_callers_ids(runtime, forwarded):
    assert compose_cli.main(["exec", "--as-me", "web", "sh"], runtime, ()) is None
    assert forwarded == [["exec", "--user=4242:4343", "web", "sh"]]  # fakes.ME


@pytest.mark.parametrize("argv, code", [
    (["exec", "-u", "0:0", "web", "sh"], None), (["exec", "web", "sh"], None),
    (["exec", "-u", "postgres", "web", "sh"], 1), (["exec", "--user=1000", "web", "sh"], 1),
])
def test_exec_takes_numeric_users_only(runtime, forwarded, capsys, argv, code):
    assert compose_cli.main(argv, runtime, ()) == code
    assert forwarded == ([] if code else [argv])


def test_exec_as_a_local_user_reaches_compose_as_numeric_ids(runtime, forwarded, capsys):
    assert compose_cli.main(["exec", "--as", "alice", "web", "sh"], runtime, ()) is None
    assert forwarded == [["exec", "--user=4242:4343", "web", "sh"]]
    assert "Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err
