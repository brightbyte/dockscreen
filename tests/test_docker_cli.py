import pytest
from fakes import FakeDocker, compose_project, make_runtime

from dockscreen import docker_cli
from dockscreen.host import config
from dockscreen.host.dockerclient import Docker

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]


@pytest.mark.parametrize("argv", [["ps"], ["compose", "ps"], ["run", "img"]])
def test_a_config_file_that_cannot_be_trusted_stops_everything(monkeypatch, capsys, argv):
    def broken():
        raise config.ConfigError("/home/me/.config/dockscreen/config.toml: /home/me is writable by others")
    monkeypatch.setattr(docker_cli, "load_runtime", broken)

    assert docker_cli.main(argv) == 1
    assert "refusing: config file /home/me/.config" in capsys.readouterr().err


def test_a_missing_docker_is_reported_without_a_traceback(monkeypatch, tmp_path, capsys):
    missing = Docker(str(tmp_path / "no-docker"))
    monkeypatch.setattr(docker_cli, "load_runtime", lambda: make_runtime(docker=missing))

    assert docker_cli.main(["run", "img"]) == 1
    assert capsys.readouterr().err == "[dockscreen] 'docker' not found in PATH\n"


def dispatch(argv, docker=None, **fields):
    """Runs argv as `dockscreen argv` with docker, by default one whose image runs as uid 100000 (app);
    returns (exit status, the argv lists docker was replaced with).
    """
    docker = docker or FakeDocker(image_user="app")
    return docker_cli._dispatch(argv, make_runtime(docker=docker, **fields)), docker.executed


# --- routing ---------------------------------------------------------------

def test_compose_is_routed_to_dockscreen():
    assert dispatch(["compose", "-f", "a.yml", "ps"])[1] == [["compose", "-f", "a.yml", "ps"]]


@pytest.mark.parametrize("argv", [[], ["--help"], ["-h"], ["help"]])
def test_the_overview_precedes_dockers_own_help(capsys, argv):
    assert dispatch(argv)[1] == [argv]
    out = capsys.readouterr().out
    assert out.startswith("Usage:  dockscreen [OPTIONS] COMMAND")
    assert "--strict-screen" in out and "  run " in out and "  compose " in out
    assert out.rstrip().endswith("Docker's own help follows:")


@pytest.mark.parametrize("argv, routed_argv", [
    (["run", "--help"], ["run", "--help"]),
    (["help", "run"], ["run", "--help"]),
    (["container", "start", "--help"], ["container", "start", "--help"]),
    (["start", "-h"], ["start", "-h"]),
])
def test_a_command_dockscreen_audits_gets_our_help_then_dockers(capsys, argv, routed_argv):
    assert dispatch(argv)[1] == [routed_argv]
    assert capsys.readouterr().out.startswith("Usage:  dockscreen ")


def test_run_dash_h_is_the_hostname_as_in_docker(capsys):
    dispatch(["run", "-h"])
    assert capsys.readouterr().out == ""  # not help: run is attempted, and docker says what is missing


@pytest.mark.parametrize("argv", [["audit", "--help"], ["help", "audit"], ["audit", "-h"]])
def test_audit_gets_only_our_help(capsys, argv):
    assert dispatch(argv) == (0, [])
    out = capsys.readouterr().out
    assert out.startswith("Usage:  dockscreen [--allow-me] [--strict-screen] audit") and "Exit status" in out


@pytest.mark.parametrize("argv", [["help", "ps"], ["ps", "--help"]])
def test_commands_dockscreen_leaves_alone_get_dockers_help(capsys, argv):
    assert dispatch(argv)[1] == [["ps", "--help"]] and capsys.readouterr().out == ""


def test_help_compose_is_the_compose_help():
    assert dispatch(["help", "compose", "up"])[1] == [["compose", "up", "--help"]]


def test_docker_options_before_compose_are_refused():
    assert dispatch(["--context", "x", "compose", "up"]) == (1, [])


@pytest.mark.parametrize("argv", [["ps"], ["images", "-a"], ["--version"], [],
                                  ["exec", "-u", "0:0", "c", "sh"],
                                  ["run", "--help"], ["run"], ["start", "--help"], ["container", "ls"]])
def test_other_commands_pass_through_unchanged(argv):
    assert dispatch(argv)[1] == [argv]


def test_commands_that_are_not_screened_say_nothing(capsys):
    assert dispatch(["ps"])[1] == [["ps"]] and capsys.readouterr().err == ""


@pytest.mark.parametrize("argv", [["exec", "-u", "root", "c", "sh"], ["exec", "-itu0", "c", "sh"],
                                  ["container", "exec", "--user=www-data", "c", "sh"]])
def test_exec_takes_numeric_users_only(argv, capsys):
    assert dispatch(argv) == (1, [])
    assert "--user takes numeric ids as uid:gid" in capsys.readouterr().err


def test_exec_as_a_local_user_reaches_docker_as_numeric_ids():
    executed = dispatch(["-l", "debug", "container", "exec", "--as=alice", "c", "sh"])[1]
    assert executed == [["-l", "debug", "container", "exec", "--user=4242:4343", "c", "sh"]]


def test_exec_as_me_reaches_docker_as_the_callers_ids():
    executed = dispatch(["exec", "--as-me", "c", "sh"])[1]
    assert executed == [["exec", "--user=4242:4343", "c", "sh"]]  # fakes.ME


def test_our_options_before_compose_reach_compose(tmp_path):
    mine = {"name": "proj", "services": {"web": {"image": "x:1", "user": "4242:4343"}}}  # fakes.ME
    runtime, recorder = compose_project(tmp_path, mine)
    assert docker_cli._dispatch(["--allow-me", "compose", "up"], runtime) == 0  # your ids, allowed
    assert recorder.children[-1][-1] == "up" and runtime.docker.forwarded == []


def test_allow_me_before_the_subcommand_reaches_the_gate_and_not_docker():
    own = FakeDocker(image_user="4242:4343")  # fakes.ME
    assert dispatch(["--allow-me", "run", "img"], own) == (42, [])
    assert dispatch(["--allow-me", "compose", "ps"])[1] == [["compose", "ps"]]


@pytest.mark.parametrize("argv, expected", [
    (["create", "-it", "img"], ["create", *DEFAULTS, "-it", "img"]),
    (["container", "create", "img"], ["container", "create", *DEFAULTS, "img"]),
    (["-l", "debug", "create", "img"], ["-l", "debug", "create", *DEFAULTS, "img"]),
])
def test_create_gets_the_hardening_defaults_and_nothing_else(argv, expected):
    assert dispatch(argv)[1] == [expected]


def test_create_resolves_as_and_keeps_everything_else(capsys):
    executed = dispatch(["create", "-it", "--as", "alice", "--name", "x", "img", "sh", "-c", "id"])[1]
    assert executed == [
        ["create", *DEFAULTS, "-it", "--user=4242:4343", "--name", "x", "img", "sh", "-c", "id"]]
    assert "Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


@pytest.mark.parametrize("flags", [["--as", "ghost"], ["--user", "alice"]])
def test_create_with_a_user_that_cannot_be_used_is_refused(flags):
    assert dispatch(["create", *flags, "img"]) == (1, [])


def test_create_with_an_unreadable_command_line_is_left_to_docker():
    assert dispatch(["create", "--name"])[1] == [["create", *DEFAULTS, "--name"]]


def test_start_is_checked_then_passed_through():
    assert dispatch(["start", "-a", "c1"])[1] == [["start", "-a", "c1"]]
    assert dispatch(["container", "restart", "c1"], FakeDocker(image_user="")) == (1, [])


def test_start_ends_with_the_verdict_before_docker_runs(capsys):
    assert dispatch(["start", "c1"])[1] == [["start", "c1"]]
    assert capsys.readouterr().err == "[dockscreen] \u2714 audit passed\n"


def test_run_goes_through_the_gate():
    assert dispatch(["container", "run", "--rm", "img"]) == (42, [])


@pytest.mark.parametrize("env, argv", [
    ({"DOCKER_HOST": "tcp://10.0.0.1:2375"}, ["run", "img"]),
    ({"DOCKER_CONTEXT": "prod"}, ["run", "img"]),
    ({}, ["-H", "ssh://x", "run", "img"]),
    ({}, ["--context=prod", "start", "c"]),
])
def test_remote_daemons_are_refused(monkeypatch, env, argv, capsys):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert dispatch(argv)[0] == 1
    assert "not the default local one" in capsys.readouterr().err


def test_a_non_default_current_context_is_refused():
    assert dispatch(["run", "img"], FakeDocker(image_user="app", context="rootless"))[0] == 1


def test_local_unix_socket_is_fine(monkeypatch):
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    assert dispatch(["run", "img"])[0] == 42


# --- audit -----------------------------------------------------------------

def test_docker_audit_is_routed_to_the_audit(capsys):
    assert dispatch(["audit", "img"]) == (0, [])
    assert "runs as uid 100000" in capsys.readouterr().out


def test_strict_screen_is_passed_to_the_audit():
    def privileged():  # a command line finding: it fails only a strict audit
        return FakeDocker(image_user="nobody", info_extra={"HostConfig": {"Privileged": True}})

    assert dispatch(["audit", "img"], privileged())[0] == 0
    assert dispatch(["--strict-screen", "audit", "img"], privileged())[0] == 1


@pytest.mark.parametrize("argv", [["--strict-screen", "run", "img"], ["--strict-screen", "compose", "up"],
                                  ["--strict-screen", "ps"], ["--strict-screen"]])
def test_strict_screen_is_refused_where_it_is_not_supported(argv, capsys):
    assert dispatch(argv) == (1, [])
    assert "--strict-screen is only supported for audit so far" in capsys.readouterr().err


def test_docker_audit_without_an_image_prints_usage(capsys):
    assert dispatch(["audit"])[0] == 2
    assert "usage: dockscreen [--allow-me] [--strict-screen] audit" in capsys.readouterr().err


def test_docker_audit_needs_a_local_daemon(monkeypatch, capsys):
    monkeypatch.setenv("DOCKER_HOST", "tcp://10.0.0.1:2375")
    assert dispatch(["audit", "img"])[0] == 1
    assert "not the default local one" in capsys.readouterr().err


def test_container_audit_is_not_a_thing():
    assert dispatch(["container", "audit"])[1] == [["container", "audit"]]
