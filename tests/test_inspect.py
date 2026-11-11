import os
import subprocess

import pytest
from fakes import make_runtime

from dockscreen.host import config
from dockscreen.host.docker import Docker, DockerError
from dockscreen.model.project import ProjectLocation
from dockscreen.policy.finding import Verdict
from dockscreen.screen import inspect


def test_project_directory_is_dir_of_first_file(tmp_path):
    runtime = make_runtime(env={})
    result = inspect._project_location(["-f", "a/x.yml", "-f", "b/y.yml"], str(tmp_path), runtime)
    assert result == ProjectLocation(str(tmp_path / "a"))


def test_project_directory_option_wins_over_file(tmp_path):
    result = inspect._project_location(
        ["-f", "a/x.yml", "--project-directory=b"], str(tmp_path), make_runtime(env={}))
    assert result.directory == str(tmp_path / "b")


def test_project_directory_from_compose_file_env(tmp_path):
    env = {"COMPOSE_FILE": "a/x.yml:b/y.yml"}
    location = inspect._project_location([], str(tmp_path), make_runtime(env=env))
    assert location.directory == str(tmp_path / "a")


def test_project_directory_searches_parents(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    mine = make_runtime(env={}, me=(os.getuid(), os.getgid()))  # the directories walked must be the caller's
    assert inspect._project_location([], str(tmp_path / "sub"), mine).directory == str(tmp_path)


def test_a_stdin_compose_file_cannot_be_inspected(tmp_path):
    with pytest.raises(DockerError):
        inspect._project_location(["-f", "-"], str(tmp_path), make_runtime(env={}))


def test_a_missing_compose_file_cannot_be_inspected(tmp_path):
    with pytest.raises(DockerError):
        inspect._project_location([], str(tmp_path), make_runtime(env={}))


def test_sensitive_paths_are_found_inside_a_directory_after_resolving_symlinks(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    os.symlink(home, tmp_path / "link-to-home")

    assert inspect._sensitive_inside(str(home / "code"), make_runtime(env={})) == []
    assert str(home) in inspect._sensitive_inside(str(tmp_path / "link-to-home"), make_runtime(env={}))
    assert "/etc" in inspect._sensitive_inside("/", make_runtime(env={}))


def test_the_sensitive_paths_in_each_configured_mount_dir_are_found(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    settings = config.Config(mount_dirs=(str(home / "code"), str(tmp_path)))

    found = inspect.sensitive_mount_dirs(make_runtime(env={}, settings=settings))
    assert found[str(home / "code")] == []
    assert found[str(tmp_path)][0] == str(home)  # the config file in it is too


def test_a_project_directory_containing_the_home_directory_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "compose.yaml").write_text("")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(inspect.ProjectRefused) as refused:
        inspect.project([], make_runtime())
    assert [f.verdict for f in refused.value.findings] == [Verdict.REFUSED]
    assert "contains" in str(refused.value.findings[0])


def test_the_walk_up_stops_at_the_home_directory(tmp_path):
    (tmp_path / "compose.yaml").write_text("")  # a stray file in "home"
    (tmp_path / "work").mkdir()
    stray = inspect._find_compose_dir(str(tmp_path / "work"), (), home=str(tmp_path), uid=os.getuid())
    assert stray == ProjectLocation(str(tmp_path), foreign=True)
    found = inspect._find_compose_dir(str(tmp_path / "work"), (), home="/elsewhere", uid=os.getuid())
    assert found == ProjectLocation(str(tmp_path))


def test_the_walk_up_stops_at_a_directory_owned_by_someone_else(tmp_path):
    (tmp_path / "work").mkdir()
    with pytest.raises(DockerError, match="no compose file found"):
        # uid 12345 owns nothing here: the first parent already belongs to someone else
        inspect._find_compose_dir(str(tmp_path / "work"), (), home="/elsewhere", uid=12345)


def test_the_starting_directory_is_used_whoever_owns_it(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    found = inspect._find_compose_dir(str(tmp_path), (), home="/elsewhere", uid=12345)
    assert found == ProjectLocation(str(tmp_path))


@pytest.mark.parametrize("line", [
    "COMPOSE_FILE=other.yml", "export COMPOSE_FILE=a:b", "  COMPOSE_PATH_SEPARATOR=;",
])
def test_compose_vars_in_dotenv_make_the_project_directory_unverifiable(tmp_path, line):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text(f"OTHER=1\n{line}\n")
    location = inspect._project_location([], str(tmp_path), make_runtime(env={}))
    assert location.redirects == (str(tmp_path / ".env"),)


def test_dotenv_in_a_directory_on_the_way_up_is_scanned_too(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    mine = make_runtime(env={}, me=(os.getuid(), os.getgid()))  # the directories walked must be the caller's
    location = inspect._project_location([], str(tmp_path / "sub"), mine)
    assert location == ProjectLocation(str(tmp_path), redirects=(str(tmp_path / "sub" / ".env"),))


def test_unrelated_dotenv_variables_are_fine_and_explicit_files_skip_the_scan(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text("MY_COMPOSE_FILE=x\nPASSWORD=y\n")
    found = inspect._project_location([], str(tmp_path), make_runtime(env={}))
    assert found == ProjectLocation(str(tmp_path))

    (tmp_path / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    runtime = make_runtime(env={})
    location = inspect._project_location(["-f", "compose.yaml"], str(tmp_path), runtime)
    assert location == ProjectLocation(str(tmp_path))


def test_config_is_loaded_without_env_resolution(monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    docker = Docker.new_for_testing(fake_run)
    inspect._load_config(["-f", "a.yml"], docker)
    assert "--no-env-resolution" in seen[0] and seen[0][:4] == ["docker", "compose", "-f", "a.yml"]
