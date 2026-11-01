"""`harden` pulls and builds as `up` would, then writes a user for the services whose image needs one."""
import json

from fakes import ME, FakeImages, compose_project

from dockscreen.commands import compose_harden

UID, GID = ME


def project(**services):
    """Services set up to pass everything except what the test is about; none sets a user by default."""
    hardened = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    return {"name": "proj", "services": {
        name: {"image": f"{name}:1", **hardened, **fields} for name, fields in services.items()}}


def setup(tmp_path, config, images, **kwargs):
    """(runtime, recorder) for the project config in tmp_path (compose_project takes kwargs)."""
    return compose_project(tmp_path, config, images, **kwargs)


def pulls(recorder):
    return [cmd[-3:] for cmd in recorder.children if "pull" in cmd]


def test_harden_writes_nothing_for_a_root_image_and_never_the_pull_pin(capsys, tmp_path):
    config = project(web={"pull_policy": "always"}, db={})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    runtime, recorder = setup(tmp_path, config, images, active=("web", "db"))

    assert compose_harden.harden([], [], runtime) == 0

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

    assert compose_harden.harden([], [], runtime) == 0

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

    assert compose_harden.harden([], [], runtime) == 0
    captured = capsys.readouterr()
    assert '    user: "${UID}:${GID}"' in captured.out
    assert "reads the checked config differently" not in captured.out + captured.err


def test_harden_leaves_a_user_the_config_file_sets_for_the_image(capsys, tmp_path):
    from dockscreen.host import config as configuration
    settings = configuration.Config(images={"docker.io/library/db": configuration.Section(user=(900, 900))})
    config = project(db={"user": "900:900", "volumes": [
        {"type": "bind", "source": str(tmp_path / "data"), "target": "/data"}]})
    images = FakeImages(users={"db:1": "app"}, digests={"db:1": ["db@sha256:x"]})
    runtime, _ = setup(tmp_path, config, images, active=("db",), settings=settings)

    assert compose_harden.harden([], [], runtime) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "services: {}"  # nothing to fix


def test_harden_does_not_pull_or_build_while_other_problems_remain(capsys, tmp_path):
    config = project(web={"build": {"context": "/"}})  # a build context outside the project: no safe fix
    runtime, recorder = setup(tmp_path, config, FakeImages(users={"web:1": ""}))

    assert compose_harden.harden([], [], runtime) == 1

    captured = capsys.readouterr()
    assert "nothing was pulled or built" in captured.err
    assert "cannot fix automatically" in captured.err
    assert recorder.children == []


def test_harden_reports_a_failed_pull_as_a_problem_it_cannot_fix(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={}), FakeImages(users={}, local=set()), codes={"pull": 1})
    assert compose_harden.harden([], [], runtime) == 1
    assert "cannot fix automatically: docker compose pull web failed" in capsys.readouterr().err
