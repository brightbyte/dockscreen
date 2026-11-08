"""`harden`: the fixes it makes, the patch it writes, and the users it sets once it has pulled and built as
`up` would."""
import json
import os

import pytest
from fakes import ME, FakeImages, compose_line, compose_project, project_of, rules, texts

from dockscreen.commands import compose_harden
from dockscreen.model.origin import Origin
from dockscreen.screen import policy

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

    assert compose_harden.harden(compose_line("harden"), runtime) == 0

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

    assert compose_harden.harden(compose_line("harden"), runtime) == 0

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

    assert compose_harden.harden(compose_line("harden"), runtime) == 0
    captured = capsys.readouterr()
    assert '    user: "${UID}:${GID}"' in captured.out
    assert "reads the checked config differently" not in captured.out + captured.err


def test_harden_fixes_no_user_when_compose_reads_the_patched_config_back_differently(capsys, tmp_path):
    runtime, recorder = setup(tmp_path, project(web={}), FakeImages(users={"web:1": "app"}),
                              reads=lambda c: {**c, "name": "other"})
    assert compose_harden.harden(compose_line("harden"), runtime) == 1
    assert "reads the checked config differently at config.name" in capsys.readouterr().err
    assert recorder.children == []


def test_harden_leaves_a_user_the_config_file_sets_for_the_image(capsys, tmp_path):
    from dockscreen.host import config as configuration
    section = configuration.ConfigSection(user=(900, 900))
    settings = configuration.Config(images={"docker.io/library/db": section})
    config = project(db={"user": "900:900", "volumes": [
        {"type": "bind", "source": str(tmp_path / "data"), "target": "/data"}]})
    images = FakeImages(users={"db:1": "app"}, digests={"db:1": ["db@sha256:x"]})
    runtime, _ = setup(tmp_path, config, images, active=("db",), settings=settings)

    assert compose_harden.harden(compose_line("harden"), runtime) == 0
    assert capsys.readouterr().out.splitlines()[-1] == "services: {}"  # nothing to fix


def test_harden_does_not_pull_or_build_while_other_problems_remain(capsys, tmp_path):
    config = project(web={"build": {"context": "/"}})  # a build context outside the project: no safe fix
    runtime, recorder = setup(tmp_path, config, FakeImages(users={"web:1": ""}))

    assert compose_harden.harden(compose_line("harden"), runtime) == 1

    captured = capsys.readouterr()
    assert "nothing was pulled or built" in captured.err
    assert "cannot fix automatically" in captured.err
    assert recorder.children == []


def test_harden_checks_the_patched_project_as_up_would_and_its_name_too(capsys, tmp_path):
    images = FakeImages(users={"web:1": "app"})
    images.project_dirs = ["/elsewhere"]  # another project's containers have the name
    runtime, recorder = setup(tmp_path, project(web={}), images)

    assert compose_harden.harden(compose_line("harden"), runtime) == 1

    out = capsys.readouterr().out
    assert "# not fixed: project name 'proj' is used by containers made from '/elsewhere'" in out
    assert pulls(recorder) == []


def test_harden_reports_a_failed_pull_as_a_problem_it_cannot_fix(capsys, tmp_path):
    runtime, _ = setup(tmp_path, project(web={}), FakeImages(users={}, local=set()), codes={"pull": 1})
    assert compose_harden.harden(compose_line("harden"), runtime) == 1
    assert "cannot fix automatically: docker compose pull web failed" in capsys.readouterr().err


# --- the fixes and the patch ------------------------------------------------

@pytest.fixture
def project_dir(tmp_path):
    """A project directory with a data directory inside it, and an escape symlink to one outside."""
    (tmp_path / "outside").mkdir()
    root = tmp_path / "project"
    root.mkdir()
    (root / "data").mkdir()
    os.symlink(tmp_path / "outside", root / "escape")
    return root


def service(**overrides):
    """A service that satisfies every requirement; tests override one thing at a time."""
    return {"user": f"{UID}:{GID}", "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"],
            **overrides}


def config(**fields):
    return {"name": "proj", "services": {"web": fields}}


def compliant(**fields):
    return config(**service(**fields))


def context(directory, extra_dirs=()):
    return policy.Policy(rules(me=(UID, GID), allow_me=True),
                          tuple(str(d) for d in extra_dirs))


def check(directory, config):
    return context(directory).check_project(project_of({"name": "proj", **config}, directory))


def bind(source):
    return {"type": "bind", "source": str(source), "target": "/x"}


def test_patch_resets_removed_keys_and_overrides_changed_ones():
    original = config(user="0:0", privileged=True, group_add=["0", str(GID)], image="x")
    fixed = compose_harden._fix_config(project_of(original, "/proj"), context("/proj"))

    lines = compose_harden._render(original, fixed).splitlines()

    assert '    user: "${UID}:${GID}"' in lines
    assert any("--allow-me" in line and line.startswith("# note") for line in lines)
    assert "    privileged: !reset null" in lines
    assert "    group_add: !reset null" in lines
    # untouched keys are not repeated
    assert not any("image" in line for line in lines)


def test_patch_for_compliant_config_is_empty():
    original = compliant()
    fixed = compose_harden._fix_config(project_of(original, "/proj"), context("/proj"))
    assert compose_harden._render(original, fixed).splitlines()[-1] == "services: {}"


def test_unfixed_problems_are_listed_as_comments():
    original = compliant()
    assert "# not fixed: bind mount /etc" in compose_harden._render(original, original, ["bind mount /etc"])


def test_fix_command_prints_patch_and_fails_when_problems_remain(capsys, tmp_path):
    original = config(user="0:0", build={"context": "/"})
    runtime, _ = compose_project(tmp_path, original)

    assert compose_harden.harden(compose_line("harden"), runtime) == 1

    captured = capsys.readouterr()
    assert "services:" in captured.out and "user:" in captured.out
    assert "cannot fix automatically" in captured.err


def test_patch_replaces_mount_list_and_tells_user_to_edit_placeholders(tmp_path):
    original = compliant(volumes=[{"type": "bind", "source": "/etc", "target": "/e"}])
    fixed = compose_harden._fix_config(project_of(original, tmp_path), context(tmp_path))

    text = compose_harden._render(original, fixed)

    assert '    volumes: !override [{"type": "bind", "source": "./ETC", "target": "/e"}]' in text
    assert "# edit: service web: mount source /etc was replaced by the placeholder ./ETC" in text


def test_fix_config_leaves_a_vetted_unset_user_alone_and_fixes_the_rest():
    config = project(web={}, db={})
    fixed = compose_harden._fix_config(project_of(config, origins={"web": {"user": Origin.IMAGE}}),
                                       policy.Policy(rules()))
    assert "user" not in fixed["services"]["web"]
    assert fixed["services"]["db"]["user"] == compose_harden._USER_TEMPLATE


def test_patch_header_names_the_command():
    assert "`dockscreen harden`" in compose_harden._HEADER


def test_fix_config_leaves_nothing_fixable(project_dir):
    config = {"services": {"web": {
        "user": "0:0", "group_add": ["0", "nogroup"], "privileged": True, "cap_add": ["ALL"],
        "devices": ["/dev/sda"], "security_opt": ["seccomp=unconfined"], "network_mode": "host",
        "volumes_from": ["container:x", "db"], "runtime": "nvidia",
    }}}
    fixed = compose_harden._fix_config(project_of(config, project_dir), context(project_dir))
    assert fixed["services"]["web"] == {
        "user": compose_harden._USER_TEMPLATE, "security_opt": ["no-new-privileges:true"],
        "cap_drop": ["ALL"], "volumes_from": ["db"],
    }
    resolved = compose_harden._as_compose_reads(fixed, context(project_dir), str(project_dir))
    assert check(project_dir, resolved) == []


def test_fix_config_does_not_touch_input_and_keeps_unfixable_problems(project_dir):
    config = {"services": {"web": service(privileged=True, build={"context": "/"}, provider={"type": "x"})}}
    fixed = compose_harden._fix_config(project_of(config, project_dir), context(project_dir))
    assert config["services"]["web"]["privileged"] is True
    assert texts(check(project_dir, fixed)) == [
        "service web: key 'provider' is not on the allow list",
        f"service web: build context '/' is outside {project_dir}",
    ]


def test_fix_config_replaces_bad_mount_sources_with_relative_upper_case_placeholders(project_dir):
    mounts = [
        {"type": "bind", "source": "/etc", "target": "/e", "read_only": True},
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/s"},
        {"type": "bind", "source": str(project_dir / "escape"), "target": "/x"},  # symlink out
        {"type": "bind", "source": str(project_dir / "data"), "target": "/d"},  # fine, kept as is
        {"type": "volume", "source": "cache", "target": "/c"},
    ]
    config = {"services": {"web": service(volumes=mounts)}}

    fixed = compose_harden._fix_config(project_of(config, project_dir), context(project_dir))

    web = fixed["services"]["web"]["volumes"]
    assert [m["source"] for m in web] == [
        "./ETC", "./VAR_RUN_DOCKER.SOCK", "./ESCAPE", str(project_dir / "data"), "cache"]
    assert web[0]["read_only"] is True  # other mount attributes survive
    assert texts(check(project_dir, fixed)) == []
    assert config["services"]["web"]["volumes"] == mounts
    # compose reads the placeholders relative to the project, and the result still passes
    resolved = compose_harden._as_compose_reads(fixed, context(project_dir), str(project_dir))
    assert [m["source"] for m in resolved["services"]["web"]["volumes"]][:2] == [
        str(project_dir / "ETC"), str(project_dir / "VAR_RUN_DOCKER.SOCK")]
    assert check(project_dir, resolved) == []


def test_fix_config_keeps_a_compliant_service(project_dir):
    config = {"services": {"web": service()}}
    assert compose_harden._fix_config(project_of(config, project_dir), context(project_dir)) == config


def test_fix_config_keeps_mounts_from_extra_dirs(project_dir):
    outside = project_dir.parent / "outside"
    config = {"services": {"web": service(volumes=[bind(outside), bind("/etc")])}}

    fixed = compose_harden._fix_config(project_of(config, project_dir), context(project_dir, [outside]))

    assert [m["source"] for m in fixed["services"]["web"]["volumes"]] == [str(outside), "./ETC"]
