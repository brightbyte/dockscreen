"""`audit` and `harden` pull and build as `up` would, then say what happens to services without a user."""
import json

from fakes import ME, FakeImages, compose_project, make_runtime

from dockscreen import messages
from dockscreen.compose import audit
from dockscreen.compose.composeimages import USER_HELP
from dockscreen.messages import BAD, GOOD

UID, GID = ME

ROOT_FALLBACK = "running as 65534:65534 instead of root"
PIN = "user, image id and pull_policy: never fixed to what was checked, in the generated file only"


def project(**services):
    """Services set up to pass everything except what the test is about; none sets a user by default."""
    hardened = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    return {"name": "proj", "services": {
        name: {"image": f"{name}:1", **hardened, **fields} for name, fields in services.items()}}


def setup(tmp_path, config, images, **kwargs):
    """(runtime, recorder) for the project config in tmp_path (compose_project takes kwargs)."""
    return compose_project(tmp_path, config, images, **kwargs)


def report(out):
    """The report lines, each of which comes after a tab."""
    lines = out.splitlines()
    assert all(line.startswith("\t") for line in lines)
    return [line[1:] for line in lines]


def pulls(recorder):
    return [cmd[-3:] for cmd in recorder.children if "pull" in cmd]


# --- audit ----------------------------------------------------------------------

def test_audit_pulls_and_says_what_happens_to_each_service_without_a_user(capsys, tmp_path):
    config = project(web={}, db={}, cache={"user": "65534:65534"})
    images = FakeImages(users={"web:1": "", "db:1": "app", "cache:1": ""}, local={"db:1"})
    runtime, recorder = setup(tmp_path, config, images, active=("web", "db", "cache"))

    assert audit.audit([], [], runtime) == 0

    captured = capsys.readouterr()
    assert "audit passed" in captured.err
    # said before the pulling starts, on stderr so that the report on stdout stays clean
    assert captured.err.index("pulling or building the images") < captured.err.index("audit passed")
    assert "pulling or building" not in captured.out
    assert report(captured.out) == [
        (f"{GOOD} service db: no user set; image db:1 runs as uid 100000 (no local user), "
         "gid 100001 (no local group); accepted"),
        messages.notable_change(f"service web: no user set; {ROOT_FALLBACK}", USER_HELP),
        messages.routine_change(f"services db, web: {PIN}"),
    ]
    assert [cmd[-4:] for cmd in recorder.children] == [["pull", "--", "cache", "web"]]  # db is already local


def test_audit_refuses_an_image_that_chose_a_low_user(capsys, tmp_path):
    config = project(web={})
    runtime, _ = setup(tmp_path, config, FakeImages(users={"web:1": "web"}))

    assert audit.audit([], [], runtime) == 1

    assert "service web: image web:1: the image's uid 1000 exists on this host" in capsys.readouterr().err


def test_audit_does_not_pull_or_build_a_project_that_fails_the_static_checks(capsys, tmp_path):
    config = project(web={"privileged": True})
    runtime, recorder = setup(tmp_path, config, FakeImages(users={"web:1": ""}))

    assert audit.audit([], [], runtime) == 1

    captured = capsys.readouterr()
    assert "privileged is not allowed" in captured.err
    assert "nothing was pulled or built" in captured.out
    assert recorder.children == [] and not any("--services" in cmd for cmd in recorder.captured)


def test_a_failed_pull_fails_the_audit_rather_than_refusing(capsys, tmp_path):
    config = project(web={})
    runtime, _ = setup(tmp_path, config, FakeImages(users={}, local=set()), codes={"pull": 1})
    assert audit.audit([], [], runtime) == 3
    assert capsys.readouterr().err.splitlines()[-2:] == [
        f"[dockscreen] {BAD} docker compose pull web failed", "[dockscreen] \u2718 audit failed"]


def test_a_config_compose_cannot_read_fails_the_audit(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={}), FakeImages())
    (tmp_path / "compose.yaml").write_text("services: [")
    assert audit.audit([], ["--brief"], runtime) == 3
    assert capsys.readouterr().out == "\u2718 audit failed: docker compose config failed:\\x0abad yaml\n"


def test_a_project_refused_before_inspection_is_refused_not_failed(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={}), FakeImages())
    runtime = runtime._replace(home=str(tmp_path / "home"))  # the project directory holds the home directory
    assert audit.audit([], [], runtime) == 1
    err = capsys.readouterr().err
    assert f"[dockscreen] {BAD} refusing: the project directory {tmp_path} contains" in err


def test_brief_prints_only_the_verdict(capsys, tmp_path):
    config = project(web={}, db={})
    runtime, _ = setup(tmp_path, config, FakeImages(users={"web:1": "app", "db:1": "web"}),
          active=("web", "db"))
    assert audit.audit([], ["--brief"], runtime) == 1
    captured = capsys.readouterr()
    assert captured.out == ("\u2296 denied by audit: service db: image db:1: the image's uid 1000 exists "
                            "on this host (local user daniel); the image's gid 1000 exists on this host "
                            "(local group daniel)\n")
    assert captured.err == ""


def test_brief_says_passed(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={}), FakeImages(users={"web:1": "app"}))
    assert audit.audit([], ["--brief"], runtime) == 0
    assert capsys.readouterr().out == "\u2714 audit passed\n"


def test_audit_takes_only_brief(capsys):
    assert audit.audit([], ["--remote"], make_runtime()) == 2
    assert "usage: dockscreen compose [compose options] audit [--brief]" in capsys.readouterr().err


# --- harden ---------------------------------------------------------------------

def test_harden_writes_nothing_for_a_root_image_and_never_the_pull_pin(capsys, tmp_path):
    config = project(web={"pull_policy": "always"}, db={})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    runtime, recorder = setup(tmp_path, config, images, active=("web", "db"))

    assert audit.harden([], [], runtime) == 0

    out = capsys.readouterr().out
    assert out.splitlines()[-1] == "services: {}"       # nothing is needed: dockscreen does it all
    assert "pull_policy" not in out and "never" not in out  # the pin lives in the generated file only
    assert "user:" not in out.replace("sets no user", "")
    # the project's always policy: the images were looked at
    assert pulls(recorder) == [["pull", "--", "web"]]
    assert ("runs a service that sets no user as the configured default user when its image would run "
            "as root") in out


def test_harden_sets_a_user_where_the_image_chose_one_that_is_not_acceptable(capsys, tmp_path):
    config = project(web={}, db={})
    images = FakeImages(users={"web:1": "web", "db:1": "app"})
    runtime, _ = setup(tmp_path, config, images, active=("web", "db"))

    assert audit.harden([], [], runtime) == 0

    out = capsys.readouterr().out
    assert ("# note: service web: image web:1 chose a user that is not acceptable, "
            "so user is set explicitly") in out
    body = out.split("services:", 1)[1]
    assert '"web":' in body and '    user: "${UID}:${GID}"' in body
    assert "dockscreen allows that only with --allow-me" in out
    assert '"db"' not in body  # its image's own user was fine


def test_harden_looks_at_the_images_with_the_users_it_writes_resolved(capsys, tmp_path):
    # db sets a user the rules refuse with its mounts; harden gives it ${UID}:${GID}, which compose
    # interpolates when it reads the generated file back, like any other value
    config = project(web={}, db={"user": "900:900", "volumes": [
        {"type": "bind", "source": str(tmp_path / "data"), "target": "/data"}]})

    def interpolating(read):
        db = read["services"]["db"]
        return json.loads(json.dumps(read).replace("${UID}", str(UID)).replace("${GID}", str(GID))) \
            if db.get("user") == "${UID}:${GID}" else read

    runtime, _ = setup(tmp_path, config, FakeImages(users={"web:1": "app", "db:1": "app"}),
          active=("web", "db"), reads=interpolating)

    assert audit.harden([], [], runtime) == 0
    captured = capsys.readouterr()
    assert '    user: "${UID}:${GID}"' in captured.out
    assert "reads the checked config differently" not in captured.out + captured.err


def test_harden_leaves_a_user_the_config_file_sets_for_the_image(capsys, tmp_path):
    from dockscreen import config as configuration
    settings = configuration.Config(images={"docker.io/library/db": configuration.Section(user=(900, 900))})
    config = project(db={"user": "900:900", "volumes": [
        {"type": "bind", "source": str(tmp_path / "data"), "target": "/data"}]})
    images = FakeImages(users={"db:1": "app"}, digests={"db:1": ["db@sha256:x"]})
    runtime, _ = setup(tmp_path, config, images, active=("db",), settings=settings)

    assert audit.harden([], [], runtime) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "services: {}"  # nothing to fix


def test_harden_does_not_pull_or_build_while_other_problems_remain(capsys, tmp_path):
    config = project(web={"build": {"context": "/"}})  # a build context outside the project: no safe fix
    runtime, recorder = setup(tmp_path, config, FakeImages(users={"web:1": ""}))

    assert audit.harden([], [], runtime) == 1

    captured = capsys.readouterr()
    assert "nothing was pulled or built" in captured.err
    assert "cannot fix automatically" in captured.err
    assert recorder.children == []


def test_harden_reports_a_failed_pull_as_a_problem_it_cannot_fix(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={}), FakeImages(users={}, local=set()), codes={"pull": 1})
    assert audit.harden([], [], runtime) == 1
    assert "cannot fix automatically: docker compose pull web failed" in capsys.readouterr().err


def test_audit_does_not_announce_pulling_when_the_static_checks_fail(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={"privileged": True}), FakeImages())
    audit.audit([], [], runtime)
    assert "pulling or building" not in capsys.readouterr().err


def test_audit_lists_the_variables_taken_from_the_shell(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("FROMSHELL", "secret")
    config = project(web={"user": f"{UID}:{GID}", "environment": {"FROMSHELL": "secret"}})
    runtime, _ = setup(tmp_path, config, FakeImages(users={"web:1": ""}))

    audit.audit([], [], runtime)

    out = capsys.readouterr().out
    assert "service web: environment variables taken from your shell: FROMSHELL" in out
    assert "secret" not in out


def test_a_remote_daemon_is_refused_before_anything_is_pulled(monkeypatch, capsys, tmp_path):
    monkeypatch.setenv("DOCKER_HOST", "tcp://build-box:2375")
    runtime, recorder = setup(tmp_path, project(web={}), FakeImages(users={"web:1": ""}))

    assert audit.audit([], [], runtime) == 1
    assert audit.harden([], [], runtime) == 1

    assert "the daemon is not the default local one" in capsys.readouterr().err
    assert recorder.children == []
