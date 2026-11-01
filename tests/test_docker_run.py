import pytest
from fakes import FakeDocker, make_runtime

from dockscreen.commands import docker_run
from dockscreen.host import config
from dockscreen.host.dockerclient import DockerError, DockerNotFound
from dockscreen.util.messages import BAD, GOOD, WARN

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]


def runtime(docker, settings=None):
    """The Runtime of a `docker` command line run with docker and settings, by the caller fakes.ME."""
    return make_runtime(docker=docker, settings=settings or config.Config())


def test_acceptable_image_user_runs_attached_with_hardening_defaults():
    docker = FakeDocker(image_user="app", command=["echo"], open_stdin=True)

    assert docker_run.gate([], ["-i", "img", "echo"], runtime(docker)) == 42  # the container's exit code

    assert docker.calls[0] == ("create", [*DEFAULTS, "-i", "img", "echo"])
    assert docker.calls[-1] == ("start", "cid1", True, True, None)


def test_detached_run_starts_without_attaching():
    docker = FakeDocker(image_user="app")
    docker_run.gate([], ["-d", "--detach-keys=ctrl-x", "img"], runtime(docker))
    assert docker.calls[0][1][-1] == "img" and "-d" not in docker.calls[0][1]
    assert docker.calls[-1] == ("start", "cid1", False, False, "ctrl-x")


def test_an_image_choosing_a_user_the_host_has_is_refused_and_the_container_removed(capsys):
    docker = FakeDocker(image_user="web")  # uid 1000: the host has an account with that id

    assert docker_run.gate([], ["img"], runtime(docker)) == 1

    err = capsys.readouterr().err
    assert "the image's uid 1000 exists on this host (local user daniel)" in err
    assert "pass --user" not in err  # what to do about it is for helpful mode
    assert docker.names() == ["create", "inspect", "remove"]  # never started


@pytest.mark.parametrize("image_user, ids", [
    ("pg", "998:998"), ("998", "998:998"), ("app", "100000:100001"), ("424242:7", "424242:7")])
def test_without_mounts_the_images_own_non_root_user_is_kept_whatever_its_id(image_user, ids, capsys):
    docker = FakeDocker(image_user=image_user)
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    assert f"--user={ids}" in docker.calls[3][1]  # the second create: pinned
    assert "nobody" not in capsys.readouterr().err


def test_an_accepted_image_user_is_pinned_as_numbers_so_the_runtime_resolves_nothing():
    docker = FakeDocker(image_user="app")

    assert docker_run.gate([], ["img"], runtime(docker)) == 42

    # created as the image has it, checked, removed, and created again with the checked ids
    assert docker.names() == ["create", "inspect", "remove", "create", "inspect", "start"]
    assert "--user=100000:100001" not in docker.calls[0][1]
    assert docker.calls[3][1] == [*DEFAULTS, "--user=100000:100001", "img"]
    assert docker.calls[-1][:2] == ("start", "cid1")


# --- mounts: the user must be chosen explicitly --------------------------------------

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


def test_with_a_bind_mount_an_image_user_outside_the_nobody_range_is_refused(capsys):
    docker = FakeDocker(image_user="pg", info_extra=BIND)

    assert docker_run.gate([], ["-v", "/p:/p", "img"], runtime(docker)) == 1

    assert docker.names() == ["create", "inspect", "remove"]
    err = capsys.readouterr().err
    assert "the image's uid 998 is not in the nobody range 65530-65534, and there are host mounts" in err


@pytest.mark.parametrize("extra", [
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_devices_and_volumes_from_count_as_mounts(extra, capsys):
    docker = FakeDocker(image_user="app", info_extra=extra)
    assert docker_run.gate([], ["img"], runtime(docker)) == 1
    assert "not in the nobody range" in capsys.readouterr().err


def test_named_volumes_are_not_host_mounts(capsys):
    docker = FakeDocker(image_user="app", info_extra={"Mounts": [{"Type": "volume", "Name": "data"}]})
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    assert "--user=100000:100001" in docker.calls[3][1]


def test_an_image_that_is_already_nobody_is_accepted_with_mounts():
    docker = FakeDocker(image_user="nobody", info_extra=BIND)
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    assert "--user=65534:65534" in docker.calls[3][1]


def test_a_user_on_the_command_line_is_all_a_mounting_container_needs(capsys):
    docker = FakeDocker(image_user="pg", container_user="998:998", info_extra=BIND)
    assert docker_run.gate([], ["--user", "998:998", "-v", "/p:/p", "img"], runtime(docker)) == 42
    assert docker.names().count("create") == 1
    # no notice about the user, which was chosen on the command line
    assert capsys.readouterr().err.splitlines()[1:] == ["[dockscreen] \u2714 audit passed"]


def test_root_with_mounts_runs_as_the_default_user(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND)
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    assert "running as 65534:65534 instead of root" in (
        capsys.readouterr().err)


def created_env(docker):
    """The environment arguments of the last create."""
    args = [call for call in docker.calls if call[0] == "create"][-1][1]
    return [args[i + 1] for i, arg in enumerate(args) if arg == "-e"]


@pytest.mark.parametrize("image_env", [[], ["HOME=/root"]])
def test_the_default_user_that_replaces_root_gets_a_home_it_can_write_to(image_env):
    docker = FakeDocker(image_user="", image_env=image_env)
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    assert created_env(docker) == ["HOME=/tmp"]  # also over the image's own HOME, which is root's


@pytest.mark.parametrize("docker, args", [
    (FakeDocker(image_user="", image_env=["HOME=/root"]), ["-e", "HOME=/srv", "img"]),
    (FakeDocker(image_user="", image_env=["HOME=/root"], env_file=["HOME=/srv"]), ["--env-file", "f", "img"]),
])
def test_a_home_chosen_on_the_command_line_or_in_an_env_file_stays(docker, args):
    assert docker_run.gate([], args, runtime(docker)) == 42
    assert "HOME=/tmp" not in created_env(docker)


def test_the_default_home_comes_from_the_config_file_and_may_be_left_out():
    docker = FakeDocker(image_user="")
    assert docker_run.gate([], ["img"], runtime(docker, config.Config(default_home="/var/empty"))) == 42
    assert created_env(docker) == ["HOME=/var/empty"]
    left_alone = FakeDocker(image_user="", image_env=["HOME=/root"])
    assert docker_run.gate([], ["img"], runtime(left_alone, config.Config(default_home=""))) == 42
    assert created_env(left_alone) == []


def test_an_image_section_can_choose_the_home_of_the_default_user():
    settings = config.Config(images={"docker.io/library/img": config.Section(default_home="/work")})
    docker = FakeDocker(image_user="", repo_digests=["img@sha256:abc"])
    assert docker_run.gate([], ["img"], runtime(docker, settings)) == 42
    assert created_env(docker) == ["HOME=/work"]


def test_only_a_default_user_replacing_root_gets_a_home():
    accepted = FakeDocker(image_user="app")  # the image's own user: docker finds its home in passwd
    assert docker_run.gate([], ["img"], runtime(accepted)) == 42
    assert created_env(accepted) == []
    root_default = FakeDocker(image_user="")
    assert docker_run.gate([], ["img"], runtime(root_default, config.Config(default_user=(0, 0)))) == 42
    assert created_env(root_default) == []  # root has a home of its own


def test_run_says_it_adds_the_defaults_as_a_routine_change(capsys):
    docker = FakeDocker(image_user="app")
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    err = capsys.readouterr().err
    assert "added --cap-drop=ALL --security-opt=no-new-privileges:true" in err


def test_what_to_do_about_the_default_user_is_for_helpful_mode(capsys, helpful):
    assert docker_run.gate([], ["img"], runtime(FakeDocker(image_user=""))) == 42
    assert "pass --user UID:GID, --as NAME or --as-me to choose a user" in capsys.readouterr().err


def test_forcing_root_to_the_default_user_is_marked_check_this(capsys):
    docker = FakeDocker(image_user="")
    assert docker_run.gate([], ["img"], runtime(docker)) == 42
    assert "running as 65534:65534 instead of root" in (
        capsys.readouterr().err)


def test_the_default_user_comes_from_the_config_file(capsys):
    docker = FakeDocker(image_user="")
    assert docker_run.gate([], ["img"], runtime(docker, config.Config(default_user=(4000, 4001)))) == 42
    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=4000:4001"]
    assert "running as 4000:4001 instead of root" in capsys.readouterr().err


def test_a_root_default_user_is_announced_on_every_run(capsys):
    docker = FakeDocker(image_user="app")
    docker_run.gate([], ["img"], runtime(docker, config.Config(default_user=(0, 0))))
    assert "the configured default user is 0:0" in capsys.readouterr().err


# --- users the config file sets for an image repository -----------------------------

IMG_USERS = config.Config(images={"docker.io/library/img": config.Section(user=(999, 999))})


def test_a_configured_image_user_replaces_the_images_own(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND, repo_digests=["img@sha256:abc"])

    assert docker_run.gate([], ["img"], runtime(docker, IMG_USERS)) == 42

    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=999:999"]  # root included, mounts or not
    err = capsys.readouterr().err
    assert "would run as root" not in err  # the config file chose the user: routine, not a surprise
    assert "image img runs as 999:999, passed to docker as numbers" in err


def test_a_configured_user_needs_the_image_to_have_been_pulled_from_that_repository(capsys):
    docker = FakeDocker(image_user="", repo_digests=["evil.example/img@sha256:abc"])
    assert docker_run.gate([], ["img"], runtime(docker, IMG_USERS)) == 42
    assert "--user=65534:65534" in docker.calls[3][1]  # an image tagged img locally: the normal rules


# --- --allow-me ------------------------------------------------------------------

def test_an_image_whose_user_is_the_caller_needs_allow_me(capsys):
    docker = FakeDocker(image_user="4242:4343")
    assert docker_run.gate([], ["img"], runtime(docker)) == 1
    assert "the image's uid 4242 is yours; pass --allow-me to allow it" in capsys.readouterr().err

    docker = FakeDocker(image_user="4242:4343")
    assert docker_run.gate([], ["--allow-me", "img"], runtime(docker)) == 42
    assert docker.calls[0][1] == [*DEFAULTS, "img"]  # --allow-me is dockscreen's, not docker's
    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=4242:4343"]


def test_allow_me_applies_with_mounts_too():
    docker = FakeDocker(image_user="4242:4343", info_extra=BIND)
    assert docker_run.gate([], ["img"], runtime(docker), allow_me=True) == 42


@pytest.mark.parametrize("image_user", ["", "root", "0:0", "424242"])  # the last gets gid 0: no passwd entry
def test_an_image_that_would_run_as_root_is_run_as_nobody_instead(image_user, capsys):
    docker = FakeDocker(image_user=image_user, open_stdin=True)

    assert docker_run.gate([], ["-i", "img"], runtime(docker)) == 42

    creates = [call[1] for call in docker.calls if call[0] == "create"]
    assert creates == [[*DEFAULTS, "-i", "img"],
                       [*DEFAULTS, "--user=65534:65534", "-e", "HOME=/tmp", "-i", "img"]]
    assert docker.names().count("remove") == 1
    assert docker.calls[docker.names().index("remove")] == ("remove", "cid1")
    assert docker.calls[-1] == ("start", "cid1", True, True, None)
    err = capsys.readouterr().err
    assert "running as 65534:65534 instead of root" in err


@pytest.mark.parametrize("flags", [
    ["--user", "1000:1000"], ["-u", "0:0"], ["--user=0:0"], ["--as-me"], ["--as", "alice"],
])
def test_a_user_on_the_command_line_prevents_the_fallback(flags, capsys):
    docker = FakeDocker(image_user="")  # root, which would fall back without the flag
    assert docker_run.gate([], [*flags, "img"], runtime(docker)) == 42

    assert docker.names().count("create") == 1
    assert "default user" not in capsys.readouterr().err


def test_as_me_means_the_callers_ids():
    docker = FakeDocker(image_user="")
    docker_run.gate([], ["--as-me", "img"], runtime(docker))
    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]


def test_failure_to_create_the_fallback_container_is_passed_on():
    docker = FakeDocker(image_user="")
    creates = iter([(0, "cid1"), (125, None)])
    docker.create = lambda args: next(creates)
    assert docker_run.gate([], ["img"], runtime(docker)) == 125


def test_a_user_on_the_command_line_is_trusted():
    docker = FakeDocker(image_user="", container_user="1000:1000")
    assert docker_run.gate([], ["--user", "1000:1000", "img"], runtime(docker)) == 42
    assert "remove" not in docker.names()


def test_user_unknown_to_the_image_is_refused(capsys):
    docker = FakeDocker(image_user="ghost")
    assert docker_run.gate([], ["img"], runtime(docker)) == 1
    assert "not defined in the image" in capsys.readouterr().err


def test_misread_command_line_is_refused_and_cleaned_up(capsys):
    docker = FakeDocker(image_user="app", image="something-else")
    assert docker_run.gate([], ["img"], runtime(docker)) == 1
    assert "could not reliably tell the image" in capsys.readouterr().err
    assert docker.names()[-1] == "remove"

    docker = FakeDocker(image_user="app", command=["different"])
    assert docker_run.gate([], ["img", "ls", "-d"], runtime(docker)) == 1


def test_create_failure_is_passed_on():
    docker = FakeDocker(create_code=125)
    assert docker_run.gate([], ["img"], runtime(docker)) == 125
    assert docker.names() == ["create"]


def test_unreadable_command_line_is_refused(capsys):
    assert docker_run.gate([], ["--name"], runtime(FakeDocker())) == 1
    assert "cannot read the command line" in capsys.readouterr().err


# --- users on the command line ---------------------------------------------------

def test_as_resolves_a_local_account_on_the_host_and_docker_gets_ids(capsys):
    docker = FakeDocker(image_user="")  # root: would fall back if no user were given

    assert docker_run.gate([], ["--as", "alice", "img"], runtime(docker)) == 42

    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]
    assert docker.names().count("create") == 1  # a user was given: no fallback
    assert "[dockscreen] Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


def test_as_with_an_account_the_host_does_not_have_is_refused_before_anything_is_created(capsys):
    docker = FakeDocker()
    assert docker_run.gate([], ["--as", "www-data", "img"], runtime(docker)) == 1
    err = capsys.readouterr().err
    assert "user 'www-data' does not exist on this host; use --user with a numeric id" in err
    assert docker.calls == []


@pytest.mark.parametrize("flags", [["--user", "alice"], ["-u", "root"], ["--user=1000:staff"]])
def test_user_with_a_name_is_refused_before_anything_is_created(flags, capsys):
    docker = FakeDocker()
    assert docker_run.gate([], [*flags, "img"], runtime(docker)) == 1
    err = capsys.readouterr().err
    assert "--user takes numeric ids as uid:gid" in err and "--as NAME runs as a local user" in err
    assert docker.calls == []


# --- image and project sections of the config file ---------------------------------

def test_an_image_section_changes_the_rules_for_that_image():
    settings = config.Config(images={"docker.io/library/img": config.Section(default_user=(65533, 65533))})
    docker = FakeDocker(image_user="", repo_digests=["img@sha256:abc"])
    assert docker_run.gate([], ["img"], runtime(docker, settings)) == 42
    assert "--user=65533:65533" in docker.calls[3][1]


def test_a_project_section_applies_in_its_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = config.Config(projects={str(tmp_path): config.Section(user=(65532, 65532))})
    docker = FakeDocker(image_user="app")
    assert docker_run.gate([], ["img"], runtime(docker, settings)) == 42
    assert "--user=65532:65532" in docker.calls[3][1]  # configured: the image's own user is not used


def test_a_top_level_user_applies_to_every_image():
    docker = FakeDocker(image_user="web")  # would be refused: a local account
    assert docker_run.gate([], ["img"], runtime(docker, config.Config(user=(65531, 65531)))) == 42
    assert "--user=65531:65531" in docker.calls[3][1]


# --- audit -------------------------------------------------------------------------

def test_audit_says_why_a_configured_user_does_not_apply(capsys):
    assert audited_with(FakeDocker(image_user="nobody"), IMG_USERS, "img") == 0
    assert ("note: the config has a section for docker.io/library/img, but this image was not pulled from "
            "there") in capsys.readouterr().out


def report(out):
    """The report lines, each of which comes after a tab."""
    lines = out.splitlines()
    assert all(line.startswith("\t") for line in lines)
    return [line[1:] for line in lines]


def audited(docker, *args):
    return docker_run.audit([], list(args), runtime(docker))


def audited_with(docker, settings, *args):
    return docker_run.audit([], list(args), runtime(docker, settings))


def test_audit_without_mounts_creates_the_container_as_run_would_and_never_starts_it(capsys):
    docker = FakeDocker(image_user="app")
    assert audited(docker, "img") == 0
    assert report(capsys.readouterr().out) == [
        f"{GOOD} image img: runs as uid 100000 (no local user), gid 100001 (no local group); accepted",
        "  docker run would create it again with --user=100000:100001, as numbers",
        ("  docker run also adds --cap-drop=ALL --security-opt=no-new-privileges:true; "
         "later options override them"),
    ]
    assert docker.names() == ["create", "inspect", "remove"]  # nothing is started
    assert docker.calls[0][1] == [*DEFAULTS, "img"]           # pulled if missing, as run would


def test_audit_with_mounts_judges_the_image_user_with_them(capsys):
    docker = FakeDocker(image_user="app", info_extra=BIND)
    assert audited(docker, "-v", "/p:/p", "img") == 1
    out = capsys.readouterr().out
    assert "the image's uid 100000 is not in the nobody range 65530-65534, and there are host mounts" in out
    assert "pass --user UID:GID, --as NAME or --as-me to choose a user" in out


def test_audit_of_a_root_image_says_it_runs_as_the_default_user(capsys):
    assert audited(FakeDocker(image_user=""), "img") == 0
    out = report(capsys.readouterr().out)
    assert out[0] == (f"{WARN} image img: would run as uid 0 (local user root), gid 0 (local group root); "
                      "docker run would run it as the default user (65534:65534) instead")
    assert out[1] == "  docker run would create it again with --user=65534:65534, as numbers"


def test_audit_predicts_a_refusal_and_exits_one(capsys):
    assert audited(FakeDocker(image_user="web"), "img") == 1
    out = capsys.readouterr().out
    assert ("image img: would be refused (runs as uid 1000 (local user daniel), "
            "gid 1000 (local group daniel)): the image's uid 1000 exists on this host "
            "(local user daniel)") in out
    # how to get past it: on the command line, or once for the repository in the config file
    assert "\u24d8 pass --user UID:GID, --as NAME or --as-me to choose a user" in out
    assert f'set user under [images."img"] in {make_runtime().config_file}' in out


def test_run_refusals_name_the_config_file_when_helpful(capsys, helpful):
    assert docker_run.gate([], ["img"], runtime(FakeDocker(image_user="web"))) == 1
    assert f'[images."img"] in {make_runtime().config_file}' in capsys.readouterr().err


def test_audit_takes_allow_me(capsys):
    assert audited(FakeDocker(image_user="4242:4343"), "img") == 1
    assert audited(FakeDocker(image_user="4242:4343"), "--allow-me", "img") == 0


def test_audit_takes_the_whole_run_command_line(capsys):
    docker = FakeDocker(image_user="app", command=["ls", "-l"])
    assert audited(docker, "--rm", "--name", "x", "-e", "A=1", "img", "ls", "-l") == 0
    assert docker.calls[0][1] == [*DEFAULTS, "--rm", "--name", "x", "-e", "A=1", "img", "ls", "-l"]


def test_audit_with_a_user_does_not_check_the_image_but_judges_the_user(capsys):
    docker = FakeDocker(image_user="", container_user="1000:1000")
    assert audited(docker, "--user", "1000:1000", "img") == 0
    out = capsys.readouterr().out
    assert "the user is set on the command line" in out
    assert "command line: user '1000:1000': uid 1000 exists on this host (local user daniel)" in out
    assert "--strict-screen makes them fail the audit" in out
    assert docker.calls[0][1] == [*DEFAULTS, "--user=1000:1000", "img"]


def test_audit_points_out_what_a_project_could_not_ask_for(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    host = {"Privileged": True, "CapAdd": ["SYS_ADMIN"], "PidMode": "host",
            "SecurityOpt": ["no-new-privileges:true", "label=disable"], "CapDrop": ["ALL"],
            "Binds": [f"{tmp_path}/src:/src", "/etc:/host-etc:ro", "data:/data"]}
    docker = FakeDocker(image_user="nobody", info_extra={"HostConfig": host})

    assert audited(docker, "img") == 0  # run would still start it: the command line is trusted

    findings = [line for line in report(capsys.readouterr().out) if "command line:" in line]
    assert findings == [
        (f"{WARN} command line: security_opt 'label=disable' is not allowed; "
         "if bind mounts fail on SELinux, add the :z or :Z mount option instead"),
        f"{WARN} command line: privileged is not allowed",
        f"{WARN} command line: cap_add is not allowed",
        f"{WARN} command line: pid: host shares a namespace outside the project",
        (f"{WARN} command line: bind mount '/etc' is outside {tmp_path}; to allow it, add a directory that "
         f'contains it to mount_dirs under [projects."{tmp_path}"] in {make_runtime().config_file}'),
    ]  # the mount inside the current directory and the named volume are fine


def test_strict_screen_fails_the_audit_for_command_line_findings(capsys):
    docker = FakeDocker(image_user="nobody", info_extra={"HostConfig": {"Privileged": True}})
    assert docker_run.audit([], ["img"], runtime(docker), strict=True) == 1
    out = capsys.readouterr().out
    assert f"{BAD} command line: privileged is not allowed" in out  # red: it fails the audit
    assert "--strict-screen makes them fail" not in out

    assert docker_run.audit([], ["img"], runtime(FakeDocker(image_user="nobody")), strict=True) == 0


def test_audit_of_an_image_docker_cannot_create_fails(capsys):
    docker = FakeDocker(create_code=125)
    assert audited(docker, "img") == 3
    assert capsys.readouterr().err == (f"[dockscreen] {BAD} docker could not create a container for img\n"
                                       "[dockscreen] \u2718 audit failed\n")


def test_audit_without_docker_fails(capsys):
    docker = FakeDocker()
    docker.create = lambda args: (_ for _ in ()).throw(DockerNotFound("'docker' not found in PATH"))
    assert audited(docker, "--brief", "img") == 3
    assert capsys.readouterr().out == "\u2718 audit failed: 'docker' not found in PATH\n"


@pytest.mark.parametrize("args, out, code", [
    (["--brief", "img"], "\u2714 audit passed\n", 0),
    (["-v", "/p:/p", "--brief", "img"],
     ("\u2296 denied by audit: the image's uid 100000 is not in the nobody range 65530-65534, "
      "and there are host mounts (+1 more)\n"), 1),
])
def test_brief_prints_only_the_verdict(args, out, code, capsys):
    docker = FakeDocker(image_user="app", info_extra=BIND if "-v" in args else None)
    assert audited(docker, *args) == code
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (out, "")
    assert "--brief" not in docker.calls[0][1]  # ours: docker never sees it


def test_brief_with_strict_screen_names_the_command_line_finding(capsys):
    docker = FakeDocker(image_user="nobody", info_extra={"HostConfig": {"Privileged": True}})
    assert docker_run.audit([], ["--brief", "img"], runtime(docker), strict=True) == 1
    assert capsys.readouterr().out == "\u2296 denied by audit: privileged is not allowed\n"


@pytest.mark.parametrize("args", [[], ["--rm"], ["--name"]])
def test_audit_needs_an_image(args, capsys):
    assert audited(FakeDocker(), *args) == 2
    assert "usage: dockscreen [--allow-me] [--strict-screen] audit" in capsys.readouterr().err


def test_audit_fails_and_removes_the_container_when_inspection_fails(capsys):
    docker = FakeDocker()
    docker.inspect_container = lambda ref: (_ for _ in ()).throw(DockerError("boom"))
    assert audited(docker, "img") == 3
    assert ("remove", "cid1") in docker.calls
    assert "image img: could not be assessed: boom" in capsys.readouterr().out


def test_run_refuses_what_audit_calls_failed(capsys):
    docker = FakeDocker()
    docker.inspect_container = lambda ref: (_ for _ in ()).throw(DockerError("boom"))
    assert docker_run.gate([], ["img"], runtime(docker)) == 1  # not started: a failure to look is not a pass
    assert capsys.readouterr().err.splitlines() == [
        f"[dockscreen] \u25cf added {' '.join(DEFAULTS)}",  # the routine notice comes before the failure
        f"[dockscreen] {BAD} boom", "[dockscreen] \u2718 audit failed"]


def test_audit_takes_as_and_refuses_names_for_user(capsys):
    docker = FakeDocker(image_user="")
    assert audited(docker, "--as", "alice", "img") == 0
    captured = capsys.readouterr()
    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]
    assert "Resolving user alice to uid 4242, gid 4343" in captured.err

    assert audited(FakeDocker(), "--user", "alice", "img") == 1
    assert "--user takes numeric ids as uid:gid" in capsys.readouterr().err


@pytest.mark.parametrize("digests, findings", [
    (["img@sha256:abc"], []),
    ([], ["command line: security_opt 'seccomp=unconfined' is not allowed"]),
])
def test_an_image_sections_security_opts_apply_to_what_audit_points_out(digests, findings, capsys):
    section = config.Section(security_opts=("seccomp=unconfined",))
    settings = config.Config(images={"docker.io/library/img": section})
    host = {"SecurityOpt": ["no-new-privileges:true", "seccomp=unconfined"], "CapDrop": ["ALL"]}
    docker = FakeDocker(image_user="nobody", repo_digests=digests, info_extra={"HostConfig": host})
    audited_with(docker, settings, "img")
    out = capsys.readouterr().out
    assert [line[2:] for line in report(out) if "command line:" in line] == findings


def test_audit_does_not_point_out_a_user_the_config_file_sets_for_the_image(capsys):
    settings = config.Config(images={"docker.io/library/img": config.Section(user=(900, 900))})
    docker = FakeDocker(image_user="", container_user="900:900", repo_digests=["img@sha256:abc"],
                        info_extra=BIND)  # with mounts, 900 is only allowed because the config says so
    assert audited_with(docker, settings, "--user", "900:900", "-v", "/p:/p", "img") == 0
    assert "command line: user" not in capsys.readouterr().out
