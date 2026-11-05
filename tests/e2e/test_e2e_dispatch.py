"""Feature: dockscreen stands in for docker, screens what it knows, and trusts only a config file nobody else
could have written

Rules (docker_cli, commands.docker, docker_compose, ComposeCommand, runtime, config):
- the commands that start containers or build are screened; everything else goes to the real docker as
  typed, and so does everything after --skip-screening, with a warning;
- dockscreen's own options go before the command; --strict-screen is refused for the commands that do not
  support it; docker options before `compose` are refused;
- the real docker is the one the config file names, or the first on PATH that is not dockscreen; empty
  and relative PATH entries are skipped and warned about, and without a docker dockscreen stops;
- the config file is read only if it and every directory above it are owned by the caller or root and
  writable by nobody else; a file that cannot be trusted or read stops everything; a missing one is
  created, with every setting commented out.
"""

import os
import shutil
from pathlib import Path

import pytest
from realdocker import ALPINE, DOCKSCREEN, free_id, require, toml_string
from steps import (
    given_image,
    given_service,
    my_ids,
    then_failed,
    then_handed_off_unchanged,
    then_nothing_handed_off,
    then_passed_through,
    then_refused,
    then_said,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("args", [["ps", "--all"], ["images"], ["version"], ["buildx", "build", "--help"],
                                  ["container", "ls"]])
def test_commands_that_start_nothing_pass_on_unchanged(world, args):
    when_dockscreen(world, *args)
    then_passed_through(world, *args)
    then_not_screened(world)


def then_not_screened(world):
    """Then dockscreen printed no verdict: it did not look."""
    assert "audit" not in world.result.stderr, world.report()


@pytest.mark.parametrize("args", [
    pytest.param(["run", "--privileged", "-v", "/:/host", ALPINE], id="run"),
    pytest.param(["start", "some-container"], id="start"),
    pytest.param(["compose", "up"], id="compose up"),
])
def test_skip_screening_hands_the_command_on_as_typed_with_a_warning(world, args):
    given_service(world, "app", privileged=True)
    when_dockscreen(world, "--skip-screening", *args)
    then_said(world, "warning: --skip-screening given: screening is disabled.",
              "warning: nothing in this command is checked, and no defaults are added.")
    then_handed_off_unchanged(world, *args)


def test_skip_screening_after_compose_works_the_same(world):
    given_service(world, "app", privileged=True)
    when_dockscreen(world, "compose", "--skip-screening", "up")
    then_said(world, "warning: --skip-screening given: screening is disabled.")
    then_handed_off_unchanged(world, "compose", "up")


def test_skip_screening_after_the_subcommand_is_left_to_docker_to_reject(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "--skip-screening", ALPINE)
    then_failed(world, f"docker could not create a container for {ALPINE}", status=125)
    then_nothing_handed_off(world)


def test_docker_options_before_compose_are_refused(world):
    given_service(world, "app", privileged=True)
    when_dockscreen(world, "--log-level", "info", "compose", "up")
    then_status(world, 1)
    then_said(world, "docker options before `compose` are not supported")
    then_nothing_handed_off(world)


def test_help_on_a_screened_command_is_dockscreens_and_dockers(world):
    when_dockscreen(world, "run", "--help")
    then_status(world, 0)
    assert world.calls and world.calls[-1].argv == ["run", "--help"], world.report()


def test_the_real_docker_is_found_on_path_past_dockscreen(world, tmp_path):
    real = Path(world.docker.binary)
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "docker").symlink_to(DOCKSCREEN)  # dockscreen itself, which it skips
    world.config_text = ""  # no docker named
    world.env["PATH"] = f"{bin_dir}{os.pathsep}{real.parent}{os.pathsep}/usr/bin{os.pathsep}/bin"
    when_dockscreen(world, "version", "--format", "{{.Client.Version}}")
    then_status(world, 0)
    assert world.result.stdout.strip(), world.report()


def test_without_a_real_docker_dockscreen_stops(world, tmp_path):
    world.config_text = ""
    world.env["PATH"] = str(tmp_path / "nowhere")
    when_dockscreen(world, "ps")
    then_status(world, 1)
    then_said(world, "'docker' not found in PATH")


def test_empty_and_relative_path_entries_are_skipped_and_warned_about(world):
    # a docker in the current directory would be found through the empty entry
    fake = world.project_dir / "docker"
    fake.write_text("#!/bin/sh\necho planted\n")
    fake.chmod(0o755)
    world.config_text = ""
    world.env["PATH"] = f"{os.pathsep}.{os.pathsep}{Path(world.docker.binary).parent}{os.pathsep}/usr/bin"
    when_dockscreen(world, "version", "--format", "{{.Client.Version}}")
    then_said(world, "warning: PATH has empty or relative entries")
    assert "planted" not in world.output, world.report()


@pytest.mark.parametrize(("mode", "problem"), [
    pytest.param(0o620, "is writable by group or others", id="a file others can write"),
])
def test_a_config_file_others_could_have_written_stops_everything(world, mode, problem):
    when_dockscreen(world, "ps")  # writes the file
    world.config_file.chmod(mode)
    world.no_config = True  # leave it as it is
    when_dockscreen(world, "ps")
    then_refused_to_run(world, f"config file {world.config_file}: {world.config_file} {problem}")


def test_a_config_directory_others_could_have_written_stops_everything(world):
    when_dockscreen(world, "ps")
    world.config_file.parent.chmod(0o770)
    world.no_config = True
    when_dockscreen(world, "ps")
    world.config_file.parent.chmod(0o700)
    then_refused_to_run(world, f"{world.config_file.parent} is writable by group or others")


def then_refused_to_run(world, problem):
    """Then dockscreen ran nothing, saying why."""
    then_status(world, 1)
    then_said(world, problem)
    assert not world.calls, world.report()


@pytest.mark.parametrize(("toml", "problem"), [
    pytest.param("colour = true", "unknown key 'colour'", id="an unknown key"),
    pytest.param("user = 'root'", 'user must be "uid:gid" with numeric ids', id="a user name"),
    pytest.param("nobody_range = [0, 65534]", "nobody_range must be [low, high]",
                 id="root in the nobody range"),
    pytest.param("nobody_range = [65530, 65535]", "nobody_range must be [low, high]",
                 id="no id in the range"),
    pytest.param("mount_dirs = ['srv']", "mount_dirs must be a list of absolute paths",
                 id="a relative mount dir"),
    pytest.param("[images.'alpine:3']\nuser = '1:1'",
                 "images 'alpine:3' names a repository; leave out the tag", id="a tagged image"),
    pytest.param("[projects.'src']\nuser = '1:1'", "projects 'src' must be an absolute directory",
                 id="a relative project"),
    pytest.param("default_home = 'tmp'", "default_home must be an absolute path", id="a relative home"),
    pytest.param("not toml", "", id="not TOML"),
])
def test_a_config_file_that_cannot_be_read_stops_everything(world, toml, problem):
    world.config_text = f"docker = {toml_string(str(world.handoff))}\n{toml}\n"
    when_dockscreen(world, "ps")
    then_refused_to_run(world, f"config file {world.config_file}: {problem}")


def test_a_missing_config_file_is_created_showing_the_defaults(world):
    world.no_config = True
    when_dockscreen(world, "--help")
    then_said(world, f"created {world.config_file}, which shows the defaults")
    assert oct(world.config_file.stat().st_mode & 0o777) == "0o600"
    assert oct(world.config_file.parent.stat().st_mode & 0o777) == "0o700"
    assert all(not line.strip() or line.startswith(("#", "["))
               for line in world.config_file.read_text().splitlines())
    shutil.rmtree(world.config_file.parent)


def test_the_environment_does_not_configure_dockscreen(world):
    free = free_id(my_ids())
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    given_service(world, "app", user=f"{free}:{free}", volumes=["./:/src"])
    world.env.update(DOCKSCREEN_NOBODY_RANGE="[20000, 60000]", nobody_range="[20000, 60000]")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"uid {free} is not in the nobody range 65530-65534")


@pytest.mark.parametrize(("args", "said", "handed_on"), [
    pytest.param(["--help"], "dockscreen", ["--help"], id="docker --help"),
    pytest.param(["help", "run"], "dockscreen", ["run", "--help"], id="help run"),
    pytest.param(["help", "audit"], "audit", None, id="help audit"),
    pytest.param(["help", "ps"], "containers", ["ps", "--help"], id="help ps"),
    pytest.param(["help"], "dockscreen", ["help"], id="help"),
    pytest.param(["help", "compose"], "harden", ["compose", "--help"], id="help compose"),
    pytest.param(["compose", "--help"], "harden", ["compose", "--help"], id="compose --help"),
    pytest.param(["compose", "help", "up"], "dockscreen compose up", ["compose", "up", "--help"],
                 id="compose help up"),
    pytest.param(["compose", "audit", "--help"], "--brief", None, id="compose audit --help"),
    pytest.param(["compose", "fix", "-h"], "override", None, id="compose fix -h"),
    pytest.param(["compose", "help"], "harden", ["compose", "--help"], id="compose help"),
    pytest.param(["compose", "help", "ps"], "containers", ["compose", "ps", "--help"], id="compose help ps"),
])
def test_help_is_dockscreens_then_dockers(world, args, said, handed_on):
    when_dockscreen(world, *args)
    then_status(world, 0)
    then_said(world, said)
    calls = [c.argv for c in world.calls]
    assert calls == ([handed_on] if handed_on else []), world.report()


def test_compose_without_a_subcommand_is_handed_on(world):
    when_dockscreen(world, "compose", "-p", "x")
    then_passed_through(world, "compose", "-p", "x")


def test_a_docker_command_line_without_a_command_is_handed_on(world):
    when_dockscreen(world, "--log-level", "error")
    then_passed_through(world, "--log-level", "error")


@pytest.mark.parametrize(("toml", "problem"), [
    pytest.param("docker = 'docker'", "docker must be an absolute path", id="a relative docker"),
    pytest.param("images = 'alpine'", "images must be a table of sections", id="images not a table"),
    pytest.param("[images]\nalpine = 1", "images 'alpine' must be a table", id="a section not a table"),
    pytest.param("[images.alpine]\ndocker = '/x'", "images 'alpine' unknown key 'docker'",
                 id="docker in a section"),
    pytest.param("security_opts = ['']", "security_opts must be a list of security options",
                 id="an empty security option"),
    pytest.param("[images.'Not Valid']\nuser = '1:1'",
                 "images 'Not Valid': 'Not Valid' is not an image reference",
                 id="not an image reference"),
])
def test_a_config_file_that_sets_something_invalid_stops_everything(world, toml, problem):
    world.config_text = f"docker = {toml_string(str(world.handoff))}\n{toml}\n" if "docker =" not in toml \
        else f"{toml}\n"
    when_dockscreen(world, "ps")
    then_refused_to_run(world, f"config file {world.config_file}: {problem}")


def test_a_config_file_that_cannot_be_opened_stops_everything(world):
    when_dockscreen(world, "ps")
    world.config_file.chmod(0o000)
    world.no_config = True
    when_dockscreen(world, "ps")
    world.config_file.chmod(0o600)
    then_refused_to_run(world, f"config file {world.config_file}: Permission denied")
