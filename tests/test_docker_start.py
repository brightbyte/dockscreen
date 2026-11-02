import pytest
from fakes import FakeDocker, make_runtime

from dockscreen.commands import docker_start
from dockscreen.host import config
from dockscreen.util import commandline

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}
IMG_USERS = config.Config(images={"docker.io/library/img": config.Section(user=(999, 999))})


def runtime(docker, settings=None):
    """The Runtime of a `docker` command line run with docker and settings, by the caller fakes.ME."""
    return make_runtime(docker=docker, settings=settings or config.Config())


def test_existing_containers_cannot_be_rewritten_so_a_root_image_is_refused():
    docker = FakeDocker(image_user="")
    problems = docker_start.check([], ["c1"], runtime(docker))
    assert problems == [
        ("c1: cannot change the user of an existing container; it would run as the image's user, "
         "not as 65534:65534")]
    assert problems[0].help == "recreate it with --user 65534:65534"


def test_an_existing_container_already_running_as_the_pinned_user_is_accepted():
    # the image names the same numbers, so the container's user is not seen as an explicit choice
    pulled = ["img@sha256:abc"]
    docker = FakeDocker(image_user="999:999", repo_digests=pulled)
    assert docker_start.check([], ["c1"], runtime(docker, IMG_USERS)) == []
    other = FakeDocker(image_user="998:998", repo_digests=pulled)
    assert docker_start.check([], ["c1"], runtime(other, IMG_USERS))


def test_an_existing_container_with_mounts_follows_the_mount_rule_too():
    docker = FakeDocker(image_user="app", info_extra=BIND)
    problems = docker_start.check([], ["c1"], runtime(docker))
    assert problems and all("not in the nobody range" in p for p in problems)
    assert docker_start.check([], ["c1"], runtime(FakeDocker(image_user="app"))) == []  # no mounts: fine


@pytest.mark.parametrize("args, refs", [
    (["a", "b"], ["a", "b"]),
    (["-a", "-i", "a"], ["a"]),
    (["--detach-keys", "x", "a", "--attach"], ["a"]),
    (["--detach-keys=x", "a"], ["a"]),
    (["-t", "5", "a"], ["a"]),
    (["--time=5", "a", "--", "-weird"], ["a", "-weird"]),
])
def test_container_refs(args, refs):
    assert commandline.positionals(args, docker_start.VALUE_LONG, docker_start.VALUE_SHORT) == refs


def test_existing_containers_are_checked_by_the_same_rule():
    ok = FakeDocker(image_user="app")
    assert docker_start.check([], ["web1"], runtime(ok)) == []
    bad = FakeDocker(image_user="web")
    problems = docker_start.check([], ["web1"], runtime(bad))
    assert "web1: the image's uid 1000 exists on this host" in problems[0]
    assert "no such" in docker_start.check([], ["gone"], runtime(bad))[0].lower()


HARDENED = {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"]}


def test_strict_judges_what_the_command_line_that_made_the_container_asked_for():
    docker = FakeDocker(image_user="nobody", info_extra={"HostConfig": {**HARDENED, "Privileged": True}})

    assert docker_start.check([], ["c1"], runtime(docker)) == []  # the command line is trusted
    assert docker_start.check([], ["c1"], runtime(docker), strict=True) == ["c1: privileged is not allowed"]


def test_strict_refuses_a_container_without_the_defaults_since_it_cannot_be_rewritten():
    docker = FakeDocker(image_user="nobody")

    assert docker_start.check([], ["c1"], runtime(docker), strict=True) == [
        "c1: cap_drop must include ALL", "c1: security_opt must include no-new-privileges:true"]


def test_strict_judges_a_user_that_is_not_the_images_by_the_id_rules():
    docker = FakeDocker(image_user="nobody", container_user="0:0", info_extra={"HostConfig": HARDENED})

    assert docker_start.check([], ["c1"], runtime(docker)) == []
    assert docker_start.check([], ["c1"], runtime(docker), strict=True) == [
        "c1: user '0:0': uid 0 is root", "c1: user '0:0': gid 0 is root"]


def test_an_existing_container_is_judged_without_the_current_directory_which_did_not_create_it(tmp_path):
    here = str(tmp_path)
    bind = {"HostConfig": HARDENED, "Mounts": [{"Type": "bind", "Source": here, "Destination": "/w"}]}
    docker = FakeDocker(image_user="nobody", info_extra=bind)
    settings = config.Config(projects={here: config.Section(user=(999, 999))})

    # the project section of the current directory does not decide the user
    assert docker_start.check([], ["c1"], make_runtime(docker=docker, settings=settings, cwd=here)) == []
    # and the current directory does not allow bind mounts, only the configured mount_dirs do
    [refusal] = docker_start.check([], ["c1"], make_runtime(docker=docker, cwd=here), strict=True)
    assert refusal.startswith(f"c1: bind mount {here!r} is outside the configured mount_dirs, which are "
                              "none; to allow it, add a directory that contains it to mount_dirs in ")
    allowed = config.Config(mount_dirs=(here,))
    assert docker_start.check([], ["c1"], make_runtime(docker=docker, settings=allowed, cwd=here),
                              strict=True) == []
