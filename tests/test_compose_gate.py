import os

import pytest
from fakes import ME, FakeImages, compose_project, make_runtime, read_raw

from dockscreen import commandline, config
from dockscreen.compose import gate
from dockscreen.dockerclient import Docker

UID, GID = ME


def project_config(**service):
    return {"name": "proj", "services": {"web": {"image": "x:1", "user": "65534:65534", **service}}}


def up(argv, idx, runtime, allow_me=False):
    return gate.run(argv[:idx], argv[idx], argv[idx + 1:], runtime, allow_me=allow_me)


def last(recorder):
    """The command that was run on the project, and the config behind it."""
    return recorder.children[-1], recorder.configs[-1]


def test_compose_runs_from_the_hardened_config_with_the_project_pinned(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(), FakeImages(users={"x:1": "app"}),
                                        codes={"up": 7})

    code = up(["-f", str(tmp_path / "compose.yaml"), "--profile", "x", "up", "-d", "web"], 4, runtime)

    assert code == 7  # compose's exit code
    cmd, config = last(recorder)
    path = cmd[cmd.index("-f") + 1]
    # our file, directory and name replace the user's; other global options and the subcommand are kept
    assert cmd[1:] == ["compose", "--profile", "x", "-f", path, "--project-directory", str(tmp_path),
                       "--project-name", "proj", "up", "-d", "web"]
    web = config["services"]["web"]
    assert web["cap_drop"] == ["ALL"] and web["security_opt"] == ["no-new-privileges:true"]
    assert ('added cap_drop: ["ALL"] and security_opt: ["no-new-privileges:true"] where '
            "missing, in services web") in capsys.readouterr().err


def test_every_generated_file_is_private_and_removed_afterwards(tmp_path):
    modes = []
    runtime, recorder = compose_project(
        tmp_path, project_config(), FakeImages(users={"x:1": "app"}),
        on_child=lambda cmd: modes.append(os.stat(cmd[cmd.index("-f") + 1]).st_mode & 0o777))

    up(["up"], 0, runtime)

    assert modes and set(modes) == {0o600}
    for cmd in recorder.children:
        path = cmd[cmd.index("-f") + 1]
        assert not os.path.exists(path) and not os.path.exists(os.path.dirname(path))


def test_a_config_with_problems_never_reaches_compose_and_nothing_is_pulled(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(privileged=True), FakeImages())

    assert up(["up"], 0, runtime) == 1

    assert "privileged is not allowed" in capsys.readouterr().err
    assert recorder.children == [] and not any("--services" in cmd for cmd in recorder.captured)


def test_what_is_checked_is_what_runs(tmp_path):
    runtime, recorder = compose_project(tmp_path, project_config(ports=["80:80"], labels={"a": "b"}),
                                        FakeImages(users={"x:1": "app"}))
    up(["up"], 0, runtime)
    web = last(recorder)[1]["services"]["web"]
    assert web["ports"] == ["80:80"] and web["labels"] == {"a": "b"} and last(recorder)[1]["name"] == "proj"


def test_inspection_failure_and_missing_project_name_are_refusals(tmp_path, capsys):
    (tmp_path / "empty").mkdir()
    assert up(["up"], 0, make_runtime(cwd=str(tmp_path / "empty"), home=str(tmp_path))) == 1
    assert "no compose file" in capsys.readouterr().err

    nameless = project_config()
    del nameless["name"]
    runtime, recorder = compose_project(tmp_path, nameless)
    assert up(["up"], 0, runtime) == 1
    assert "config has no project name" in capsys.readouterr().err
    assert recorder.children == []


def test_the_callers_own_ids_need_allow_me(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(user=f"{UID}:{GID}"),
                                        FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, runtime) == 1
    assert f"uid {UID} is yours; pass --allow-me to allow it" in capsys.readouterr().err
    assert recorder.children == []

    assert up(["up"], 0, runtime, allow_me=True) == 0
    assert last(recorder)[1]["services"]["web"]["user"] == f"{UID}:{GID}"


def test_run_with_a_user_on_the_command_line_skips_deciding_that_services_image(
        tmp_path, capsys):
    config = no_user()
    runtime, recorder = compose_project(tmp_path, config,
                                        FakeImages(users={"x:1": "web"}))  # uid 1000: refused

    assert up(["run", "--rm", "-u", "1000:1000", "web", "sh"], 0, runtime) == 0
    assert last(recorder)[0][-6:] == ["run", "--rm", "-u", "1000:1000", "web", "sh"]


def test_run_as_a_local_user_reaches_compose_as_numeric_ids(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, no_user(),
                                        FakeImages(users={"x:1": "web"}))  # uid 1000: refused

    assert up(["run", "--as", "alice", "web", "sh"], 0, runtime) == 0
    assert last(recorder)[0][-4:] == ["run", "--user=4242:4343", "web", "sh"]
    assert "Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


def test_run_as_me_reaches_compose_as_the_callers_ids(tmp_path):
    runtime, recorder = compose_project(tmp_path, no_user(), FakeImages(users={"x:1": "web"}))

    assert up(["run", "--as-me", "web", "sh"], 0, runtime) == 0
    assert last(recorder)[0][-4:] == ["run", f"--user={UID}:{GID}", "web", "sh"]


@pytest.mark.parametrize("args, message", [
    (["run", "-u", "postgres", "web"], "--user takes numeric ids as uid:gid, not 'postgres'"),
    (["run", "--user=1000", "web"], "give the group too"),
])
def test_run_takes_numeric_users_only(tmp_path, capsys, args, message):
    runtime, recorder = compose_project(tmp_path, no_user(), FakeImages(users={"x:1": "app"}))
    assert up(args, 0, runtime) == 1
    assert message in capsys.readouterr().err and recorder.children == []


def test_no_defaults_notice_when_nothing_was_added(tmp_path, capsys):
    hardened = project_config(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    runtime, _ = compose_project(tmp_path, hardened, FakeImages(users={"x:1": "app"}))
    up(["up"], 0, runtime)
    assert capsys.readouterr().err == "[dockscreen] \u2714 audit passed\n"  # and nothing else


def test_the_verdict_is_the_last_word_before_compose_runs(tmp_path, capsys):
    seen = []
    runtime, _ = compose_project(
        tmp_path, project_config(), FakeImages(users={"x:1": "app"}),
        on_child=lambda cmd: seen.append(capsys.readouterr().err) if "up" in cmd else None)
    up(["up"], 0, runtime)
    assert seen[-1].splitlines()[-1] == "[dockscreen] \u2714 audit passed"


def test_a_refused_run_ends_with_the_verdict(tmp_path, capsys):
    runtime, _ = compose_project(tmp_path, project_config(privileged=True))
    assert up(["up"], 0, runtime) == 1
    assert capsys.readouterr().err.splitlines()[-2:] == [
        "[dockscreen] \u25cf refusing: service web: privileged is not allowed",
        "[dockscreen] \u2296 denied by audit"]


# --- services that set no user ---------------------------------------------------

def no_user(**fields):
    config = project_config(cap_drop=["ALL"], security_opt=["no-new-privileges:true"], **fields)
    del config["services"]["web"]["user"]
    return config


def test_a_root_image_runs_as_the_default_user_with_the_image_pinned_in_the_generated_file(
        tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, no_user(pull_policy="always"),
                                        FakeImages(users={"x:1": ""}), codes={"up": 3})

    assert up(["up", "-d"], 0, runtime) == 3

    web = last(recorder)[1]["services"]["web"]
    assert web["user"] == "65534:65534"
    # in the generated file only: the image that was checked is the one that runs
    assert web["pull_policy"] == "never"
    pulled = [cmd[-3:] for cmd in recorder.children if "pull" in cmd]
    assert pulled == [["pull", "--", "web"]]    # the project's policy (always) was applied first
    assert "service web: running as 65534:65534 instead of root" in capsys.readouterr().err


def test_images_are_acquired_from_a_config_that_still_has_the_projects_pull_policy(tmp_path):
    config = no_user(pull_policy="always")
    runtime, recorder = compose_project(tmp_path, config, FakeImages(users={"x:1": ""}))
    up(["up"], 0, runtime)
    # the config the images were acquired from still has the project's own policy
    assert recorder.configs[0]["services"]["web"]["pull_policy"] == "always"
    assert "user" not in recorder.configs[0]["services"]["web"]
    assert config["services"]["web"]["pull_policy"] == "always"


def test_an_acceptable_image_user_is_kept_but_pinned_as_numbers(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, no_user(), FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, runtime) == 0

    web = last(recorder)[1]["services"]["web"]
    assert web["user"] == "100000:100001" and web["pull_policy"] == "never"
    assert "default user" not in capsys.readouterr().err


def test_an_image_that_chose_a_low_user_is_refused_before_anything_runs(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, no_user(), FakeImages(users={"x:1": "web"}))

    assert up(["up"], 0, runtime) == 1

    assert "service web: image x:1: the image's uid 1000 exists on this host" in capsys.readouterr().err
    assert all("up" not in cmd for cmd in recorder.children)


def test_failing_to_pull_stops_the_run(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, no_user(),
                                        FakeImages(users={"x:1": "app"}, local=set()), codes={"pull": 1})
    assert up(["up"], 0, runtime) == 1
    assert "docker compose pull web failed" in capsys.readouterr().err
    assert [cmd[-3:] for cmd in recorder.children] == [["pull", "--", "web"]]


def test_a_service_that_is_not_started_gets_the_default_user_as_a_fail_safe(tmp_path):
    config = no_user()
    config["services"]["debug"] = {
        "image": "d:1", "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    runtime, recorder = compose_project(tmp_path, config,
                                        FakeImages(users={"x:1": "app", "d:1": ""}), active=("web",))

    up(["up", "web"], 0, runtime)

    services = last(recorder)[1]["services"]
    assert services["debug"]["user"] == "65534:65534" and "pull_policy" not in services["debug"]
    assert services["web"]["user"] == "100000:100001"


@pytest.mark.parametrize("args, kept", [
    (["-f", "a.yml", "-p", "n", "--project-directory", "d", "--profile", "x"], ["--profile", "x"]),
    (["--file=a.yml", "--project-name=n", "--project-directory=d"], []),
    (["-fa.yml", "-pn"], []),
    (["--env-file", "e", "--ansi", "never"], ["--env-file", "e", "--ansi", "never"]),
    ([], []),
])
def test_strip_options(args, kept):
    assert commandline.strip_options(args, gate.REPLACED_OPTIONS) == kept


def test_run_child_exit_codes_and_signals():
    assert Docker("docker").run_child(["true"]) == 0
    assert Docker("docker").run_child(["sh", "-c", "exit 3"]) == 3
    assert Docker("docker").run_child(["sh", "-c", "kill -TERM $$"]) == 128 + 15
    assert Docker("docker").run_child(["/nonexistent/docker"]) == 127


def test_run_child_passes_termination_to_the_child_and_restores_handlers():
    import signal
    import threading
    before = signal.getsignal(signal.SIGTERM)
    timer = threading.Timer(0.3, lambda: os.kill(os.getpid(), signal.SIGTERM))
    timer.start()
    code = Docker("docker").run_child(["sh", "-c", "trap 'exit 9' TERM; while true; do sleep 0.1; done"])
    timer.cancel()
    assert code == 9
    assert signal.getsignal(signal.SIGTERM) == before


def test_dollars_are_written_as_compose_printed_them(tmp_path):
    # `config` prints a literal $ as $$, and compose reads $$ back as a literal $: escaping again
    # would make `$$` into `$$$$` and the config would no longer be the one that was checked
    raw = []
    runtime, _ = compose_project(tmp_path, project_config(pid="$${P:-host}", labels={"a": "$$x"}),
                                 FakeImages(users={"x:1": "app"}),
                                 on_child=lambda cmd: raw.append(read_raw(cmd)))

    assert up(["up"], 0, runtime) == 0

    assert all('"$${P:-host}"' in text and '"$$x"' in text for text in raw)


def test_a_config_compose_would_read_differently_is_refused_and_not_run(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(pid="${P:-host}"),
                                        FakeImages(users={"x:1": "app"}),
                                        reads=lambda c: {**c, "name": "other"})

    assert up(["up"], 0, runtime) == 1

    assert "reads the checked config differently at config.name" in capsys.readouterr().err
    assert recorder.children == []


def test_variables_taken_from_the_shell_are_announced_by_name_and_service_but_not_run_differently(
        monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("FROMSHELL", "secret")
    shell_and_own = project_config(environment={"FROMSHELL": "secret", "OWN": "x"})
    runtime, recorder = compose_project(tmp_path, shell_and_own, FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, runtime) == 0

    err = capsys.readouterr().err
    assert "service web: environment variables taken from your shell: FROMSHELL" in err
    assert "secret" not in err
    assert last(recorder)[1]["services"]["web"]["environment"] == {"FROMSHELL": "secret", "OWN": "x"}


@pytest.mark.parametrize("env", [
    {"DOCKER_HOST": "tcp://build-box:2375"}, {"DOCKER_HOST": "ssh://me@box"}, {"DOCKER_CONTEXT": "prod"}])
def test_a_remote_daemon_is_refused_because_paths_and_ids_mean_nothing_there(
        monkeypatch, tmp_path, capsys, env):
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    runtime, recorder = compose_project(tmp_path, project_config(), FakeImages(users={"x:1": "app"}))

    assert up(["up"], 0, runtime) == 1

    assert "the daemon is not the default local one" in capsys.readouterr().err
    assert recorder.children == [] and not any("--services" in cmd for cmd in recorder.captured)


def test_a_context_option_is_refused_too(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(), FakeImages(users={"x:1": "app"}))
    assert up(["--context", "prod", "up"], 2, runtime) == 1
    assert recorder.children == []


# --- image and project sections of the config file ---------------------------------

X_DIRS = config.Config(images={"docker.io/library/x": config.Section(mount_dirs=("/srv/x",))})
X_MOUNT = {"volumes": [{"type": "bind", "source": "/srv/x/data", "target": "/data"}]}


def test_an_image_section_allows_a_mount_once_the_image_proves_its_origin(tmp_path):
    runtime, recorder = compose_project(tmp_path, project_config(**X_MOUNT),
                                        FakeImages(users={"x:1": "app"}, digests={"x:1": ["x@sha256:a"]}),
                                        settings=X_DIRS)

    assert up(["up"], 0, runtime) == 0
    assert last(recorder)[1]["services"]["web"]["volumes"][0]["source"] == "/srv/x/data"


def test_an_image_section_that_its_image_does_not_prove_is_refused_before_anything_runs(
        tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(**X_MOUNT),
                                        FakeImages(users={"x:1": "app"}),  # tagged x:1 locally, no digest
                                        settings=X_DIRS)

    assert up(["up"], 0, runtime) == 1
    # the name was enough to get past the first check; the image itself is not
    assert "service web: bind mount '/srv/x/data' is outside" in capsys.readouterr().err
    assert not any("up" in cmd for cmd in recorder.children)


def test_a_project_section_applies_to_its_directory(tmp_path, capsys):
    settings = config.Config(projects={str(tmp_path): config.Section(mount_dirs=("/srv/x",))})
    runtime, _ = compose_project(tmp_path, project_config(**X_MOUNT),
                                 FakeImages(users={"x:1": "app"}), settings=settings)
    assert up(["up"], 0, runtime) == 0

    elsewhere = config.Config(projects={"/elsewhere": config.Section(mount_dirs=("/srv/x",))})
    runtime, _ = compose_project(tmp_path, project_config(**X_MOUNT), FakeImages(users={"x:1": "app"}),
                                 settings=elsewhere)
    assert up(["up"], 0, runtime) == 1


X_USER = config.Config(images={"docker.io/library/x": config.Section(user=(900, 900))})


def inside(project):
    """A bind mount of a directory inside the project."""
    return {"volumes": [{"type": "bind", "source": str(project / "data"), "target": "/data"}]}


def test_a_service_may_name_the_user_its_image_section_sets(tmp_path, capsys):
    runtime, recorder = compose_project(tmp_path, project_config(user="900:900", **inside(tmp_path)),
                                        FakeImages(users={"x:1": "app"}, digests={"x:1": ["x@sha256:a"]}),
                                        settings=X_USER)

    assert up(["up"], 0, runtime) == 0
    assert last(recorder)[1]["services"]["web"]["user"] == "900:900"


def test_the_user_an_image_section_sets_needs_the_image_to_prove_it(tmp_path, capsys):
    runtime, _ = compose_project(tmp_path, project_config(user="900:900", **inside(tmp_path)),
                                 FakeImages(users={"x:1": "app"}),  # no digest: tagged locally
                                 settings=X_USER)

    assert up(["up"], 0, runtime) == 1
    assert "user '900:900': uid 900 is not in the nobody range" in capsys.readouterr().err
