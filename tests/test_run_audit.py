import pytest
from fakes import FakeDocker, make_runtime

from dockscreen import config
from dockscreen.dockerclient import DockerError, DockerNotFound
from dockscreen.messages import BAD, GOOD, WARN
from dockscreen.run import audit, gate

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}
IMG_USERS = config.Config(images={"docker.io/library/img": config.Section(user=(999, 999))})


def runtime(docker, settings=None):
    """The Runtime of a `docker` command line run with docker and settings, by the caller fakes.ME."""
    return make_runtime(docker=docker, settings=settings or config.Config())


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
    return audit.audit([], list(args), runtime(docker))


def audited_with(docker, settings, *args):
    return audit.audit([], list(args), runtime(docker, settings))


def test_audit_without_mounts_creates_the_container_as_run_would_and_never_starts_it(capsys):
    docker = FakeDocker(image_user="app")
    assert audited(docker, "img") == 0
    assert report(capsys.readouterr().out) == [
        f"{GOOD} image img: runs as uid 100000 (no local user), gid 100001 (no local group); accepted",
        "  docker run would create it again with --user=100000:100001, as numbers",
        "  docker run also adds --cap-drop=ALL --security-opt=no-new-privileges:true; "
        "later options override them",
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
    assert gate.run([], ["img"], runtime(FakeDocker(image_user="web"))) == 1
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
        f"{WARN} command line: security_opt 'label=disable' is not allowed; "
        "if bind mounts fail on SELinux, add the :z or :Z mount option instead",
        f"{WARN} command line: privileged is not allowed",
        f"{WARN} command line: cap_add is not allowed",
        f"{WARN} command line: pid: host shares a namespace outside the project",
        f"{WARN} command line: bind mount '/etc' is outside {tmp_path}; to allow it, add a directory that "
        f'contains it to mount_dirs under [projects."{tmp_path}"] in {make_runtime().config_file}',
    ]  # the mount inside the current directory and the named volume are fine


def test_strict_screen_fails_the_audit_for_command_line_findings(capsys):
    docker = FakeDocker(image_user="nobody", info_extra={"HostConfig": {"Privileged": True}})
    assert audit.audit([], ["img"], runtime(docker), strict=True) == 1
    out = capsys.readouterr().out
    assert f"{BAD} command line: privileged is not allowed" in out  # red: it fails the audit
    assert "--strict-screen makes them fail" not in out

    assert audit.audit([], ["img"], runtime(FakeDocker(image_user="nobody")), strict=True) == 0


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
     "\u2296 denied by audit: the image's uid 100000 is not in the nobody range 65530-65534, "
     "and there are host mounts (+1 more)\n", 1),
])
def test_brief_prints_only_the_verdict(args, out, code, capsys):
    docker = FakeDocker(image_user="app", info_extra=BIND if "-v" in args else None)
    assert audited(docker, *args) == code
    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (out, "")
    assert "--brief" not in docker.calls[0][1]  # ours: docker never sees it


def test_brief_with_strict_screen_names_the_command_line_finding(capsys):
    docker = FakeDocker(image_user="nobody", info_extra={"HostConfig": {"Privileged": True}})
    assert audit.audit([], ["--brief", "img"], runtime(docker), strict=True) == 1
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
    assert gate.run([], ["img"], runtime(docker)) == 1  # not started: a failure to look is not a pass
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
