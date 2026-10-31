import types

import pytest

from fakes import runtime

from dockscreen import docker_cli, flags
from dockscreen.compose import compose_cli

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
    assert flags.strip(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE) == (found, rest)


def test_banner_goes_to_stderr(capsys):
    flags.banner()
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "screening is disabled" in captured.err and "no defaults are added" in captured.err


def test_dockscreen_with_the_flag_is_plain_compose_with_a_warning(forwarded, monkeypatch, capsys):
    monkeypatch.setattr(compose_cli.composerun, "run", lambda *a, **k: 1 / 0)
    monkeypatch.setattr(compose_cli.screen, "passes", lambda *a: 1 / 0)

    compose_cli.main([FLAG, "-f", "a.yml", "up", "-d"], runtime())

    assert forwarded == [["-f", "a.yml", "up", "-d"]]
    assert "screening is disabled" in capsys.readouterr().err


def test_dockscreen_flag_also_skips_the_extra_subcommands(forwarded):
    compose_cli.main([FLAG, "audit"], runtime())
    assert forwarded == [["audit"]]  # compose gets it unchanged; nothing of ours runs


@pytest.mark.parametrize("argv, expected", [
    ([FLAG, "run", "--privileged", "img"], ["run", "--privileged", "img"]),
    ([FLAG, "compose", "up"], ["compose", "up"]),
    (["-H", "tcp://x", FLAG, "create", "img"], ["-H", "tcp://x", "create", "img"]),
])
def test_docker_with_the_flag_is_plain_docker_with_a_warning(monkeypatch, capsys, argv, expected):
    calls = []
    monkeypatch.setattr(docker_cli, "_passthrough", lambda a, _: calls.append(a) or 0)
    monkeypatch.setattr(docker_cli.compose_cli, "main", lambda *a: 1 / 0)

    docker_cli.main(argv)

    assert calls == [expected]  # no defaults added, no gate, no dockscreen
    assert "screening is disabled" in capsys.readouterr().err


def test_docker_without_a_global_flag_gets_no_exemption(monkeypatch):
    calls = []
    monkeypatch.setattr(docker_cli, "_passthrough", lambda a, _: calls.append(a) or 0)
    docker_cli.main(["create", "img", FLAG])  # belongs to the command
    assert calls == [["create", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "img", FLAG]]


@pytest.mark.parametrize("argv", [["--helpful", "up"], ["--verbose", "up"], ["--verbose", "--helpful", "up"]])
def test_helpful_and_verbose_are_ours_and_not_passed_on(argv):
    assert flags.strip_helpful(argv, compose_cli.GLOBAL_OPTS_WITH_VALUE) == (True, ["up"])


def test_verbose_after_the_subcommand_is_dockers_own():
    assert flags.strip_helpful(["up", "--verbose"], compose_cli.GLOBAL_OPTS_WITH_VALUE) == (
        False, ["up", "--verbose"])


@pytest.mark.parametrize("argv, helpful", [
    (["--helpful", "ps"], True), (["--verbose", "ps"], True), (["ps"], False), (["audit", "img"], True)])
def test_the_helpful_mode_follows_the_flags_and_the_audit_command(argv, helpful, monkeypatch):
    from dockscreen import messages
    monkeypatch.setattr(docker_cli, "_passthrough", lambda argv, runtime: 0)
    monkeypatch.setattr(docker_cli.gate, "audit", lambda *a, **k: 0)
    monkeypatch.setattr("dockscreen.runtime.Docker", lambda binary: types.SimpleNamespace(context=lambda: "default"))

    docker_cli.main(argv)

    assert messages._helpful is helpful


def test_compose_audit_is_helpful_and_compose_gets_the_flag(forwarded, monkeypatch):
    from dockscreen import messages
    monkeypatch.setitem(compose_cli.COMMANDS, "audit", lambda **kwargs: 0)

    compose_cli.main(["audit"], runtime())
    assert messages._helpful is True
    compose_cli.main(["--verbose", "ps"], runtime())
    assert messages._helpful is True and forwarded == [["ps"]]  # --verbose is not passed to compose
