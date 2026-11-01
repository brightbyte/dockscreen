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
