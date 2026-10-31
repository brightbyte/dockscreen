import os
import subprocess

import pytest
from fakes import make_runtime

from dockscreen import messages
from dockscreen.compose import inspect
from dockscreen.host import config
from dockscreen.host.dockerclient import Docker


def test_project_directory_is_dir_of_first_file(tmp_path):
    runtime = make_runtime(env={})
    result = inspect._project_directory(["-f", "a/x.yml", "-f", "b/y.yml"], str(tmp_path), runtime)
    assert result == str(tmp_path / "a")


def test_project_directory_option_wins_over_file(tmp_path):
    result = inspect._project_directory(
        ["-f", "a/x.yml", "--project-directory=b"], str(tmp_path), make_runtime(env={}))
    assert result == str(tmp_path / "b")


def test_project_directory_from_compose_file_env(tmp_path):
    env = {"COMPOSE_FILE": "a/x.yml:b/y.yml"}
    assert inspect._project_directory([], str(tmp_path), make_runtime(env=env)) == str(tmp_path / "a")


def test_project_directory_searches_parents(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    mine = make_runtime(env={}, me=(os.getuid(), os.getgid()))  # the directories walked must be the caller's
    assert inspect._project_directory([], str(tmp_path / "sub"), mine) == str(tmp_path)


def test_stdin_compose_file_is_refused(tmp_path):
    with pytest.raises(inspect.ScreenError):
        inspect._project_directory(["-f", "-"], str(tmp_path), make_runtime(env={}))


def test_missing_compose_file_is_refused(tmp_path):
    with pytest.raises(inspect.ScreenError):
        inspect._project_directory([], str(tmp_path), make_runtime(env={}))


def test_sensitive_paths_are_found_inside_a_directory_after_resolving_symlinks(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    os.symlink(home, tmp_path / "link-to-home")

    assert inspect._sensitive_inside(str(home / "code"), make_runtime(env={})) == []
    assert str(home) in inspect._sensitive_inside(str(tmp_path / "link-to-home"), make_runtime(env={}))
    assert "/etc" in inspect._sensitive_inside("/", make_runtime(env={}))


def test_mount_dirs_that_contain_sensitive_paths_get_a_warning(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    settings = config.Config(mount_dirs=(str(home / "code"), str(tmp_path)))

    assert inspect.mount_dir_warnings(make_runtime(env={}, settings=settings)) == [
        messages.Marked(messages.WARN, f"the configured mount dir {tmp_path} contains {home}, so containers "
                                       "can mount it")]


def test_a_project_directory_containing_the_home_directory_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "compose.yaml").write_text("")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(inspect.ScreenError, match="contains"):
        inspect.project([], make_runtime())


def test_the_walk_up_stops_at_the_home_directory(tmp_path):
    (tmp_path / "compose.yaml").write_text("")  # a stray file in "home"
    (tmp_path / "work").mkdir()
    with pytest.raises(inspect.ScreenError, match="your home directory or not yours"):
        inspect._find_compose_dir(str(tmp_path / "work"), (), home=str(tmp_path), uid=os.getuid())
    found = inspect._find_compose_dir(str(tmp_path / "work"), (), home="/elsewhere", uid=os.getuid())
    assert found == str(tmp_path)


def test_the_walk_up_stops_at_a_directory_owned_by_someone_else(tmp_path):
    (tmp_path / "work").mkdir()
    with pytest.raises(inspect.ScreenError, match="no compose file found"):
        # uid 12345 owns nothing here: the first parent already belongs to someone else
        inspect._find_compose_dir(str(tmp_path / "work"), (), home="/elsewhere", uid=12345)


def test_the_starting_directory_is_used_whoever_owns_it(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    assert inspect._find_compose_dir(str(tmp_path), (), home="/elsewhere", uid=12345) == str(tmp_path)


@pytest.mark.parametrize("line", [
    "COMPOSE_FILE=other.yml", "export COMPOSE_FILE=a:b", "  COMPOSE_PATH_SEPARATOR=;",
])
def test_compose_vars_in_dotenv_make_the_project_directory_unverifiable(tmp_path, line):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text(f"OTHER=1\n{line}\n")
    with pytest.raises(inspect.ScreenError):
        inspect._project_directory([], str(tmp_path), make_runtime(env={}))


def test_dotenv_in_a_directory_on_the_way_up_is_scanned_too(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    with pytest.raises(inspect.ScreenError):
        inspect._project_directory([], str(tmp_path / "sub"), make_runtime(env={}))


def test_unrelated_dotenv_variables_are_fine_and_explicit_files_skip_the_scan(tmp_path):
    (tmp_path / "compose.yaml").write_text("")
    (tmp_path / ".env").write_text("MY_COMPOSE_FILE=x\nPASSWORD=y\n")
    assert inspect._project_directory([], str(tmp_path), make_runtime(env={})) == str(tmp_path)

    (tmp_path / ".env").write_text("COMPOSE_FILE=elsewhere.yml\n")
    runtime = make_runtime(env={})
    assert inspect._project_directory(["-f", "compose.yaml"], str(tmp_path), runtime) == str(tmp_path)


def test_config_is_loaded_without_env_resolution(monkeypatch):
    seen = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "{}", "")

    docker = Docker.new_for_testing(fake_run)
    inspect._load_config(["-f", "a.yml"], docker)
    assert "--no-env-resolution" in seen[0] and seen[0][:4] == ["docker", "compose", "-f", "a.yml"]
