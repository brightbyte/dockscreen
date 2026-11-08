"""Feature: `docker start` and `restart` start only containers that `run` would have started

Rules (docker_start):
- every container named is checked as run checks a new one, before any of them starts;
- an existing container cannot be rewritten, so one whose user dockscreen would replace (by the default
  user or a configured one) is refused, with how to create it again;
- a container whose user was set when it was created is trusted, as `run --user` is;
- `docker create` adds the defaults and resolves --as and --as-me, and `docker exec` resolves them too;
  neither checks anything else, since the command line is trusted.
"""

import pytest
from realdocker import ALPINE
from steps import (
    given_container,
    given_env,
    given_image,
    me_user,
    my_ids,
    my_name,
    then_container,
    then_handed_off,
    then_handed_off_unchanged,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_runs_hardened,
    then_said,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("sub", [["start"], ["restart"], ["container", "start"]])
def test_a_container_that_would_run_as_root_is_refused(world, sub):
    container = given_container(world, given_image(world, ALPINE), "true")
    when_dockscreen(world, "--helpful", *sub, container)
    then_refused(world, f"{container}: cannot change the user of an existing container; it would run as the "
                        "image's user, not as 65534:65534")
    then_said(world, "recreate it with --user 65534:65534")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("sub", ["start", "restart"])
def test_a_container_created_with_a_user_is_started(world, sub):
    container = given_container(world, "--user=65534:65534", given_image(world, ALPINE), "true")
    when_dockscreen(world, sub, "-a", container)
    then_passed(world)
    then_handed_off_unchanged(world, sub, "-a", container)


def test_every_container_is_checked_before_any_starts(world):
    image = given_image(world, ALPINE)
    good = given_container(world, "--user=65534:65534", image, "true")
    bad = given_container(world, image, "true")
    when_dockscreen(world, "start", "--detach-keys", "ctrl-x", good, bad)
    then_refused(world, f"{bad}: cannot change the user")
    then_nothing_handed_off(world)


def test_a_container_of_an_image_that_runs_as_the_caller_is_refused(world, own_ids_image):
    container = given_container(world, own_ids_image)
    when_dockscreen(world, "start", container)
    then_refused(world, f"{container}: the image's uid {my_ids()[0]} is yours")
    then_nothing_handed_off(world)


def test_a_container_that_is_not_there_is_refused(world):
    when_dockscreen(world, "start", "dockscreen-e2e-absent")
    then_refused(world, "dockscreen-e2e-absent: docker container inspect failed")
    then_nothing_handed_off(world)


def test_a_daemon_that_may_not_be_this_hosts_is_refused(world):
    given_env(world, DOCKER_HOST="tcp://192.0.2.1:2375")
    when_dockscreen(world, "start", "anything")
    then_refused(world, "the daemon is not the default local one")


def test_create_adds_the_defaults_and_resolves_the_user(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "create", "--as-me", "--label=dockscreen-e2e=1", ALPINE, "true")
    then_status(world, 0)
    then_said(world, "added --cap-drop=ALL --security-opt=no-new-privileges:true")
    then_nothing_handed_off(world)
    created = [c.created for c in world.calls if c.created]
    assert len(created) == 1, world.report()
    container = then_container(world, created[0])
    assert container["Config"]["User"] == me_user()
    then_runs_hardened(world, container)


def test_create_refuses_a_user_name(world):
    when_dockscreen(world, "create", "--user", "root", ALPINE)
    then_status(world, 1)
    then_said(world, "--user takes numeric ids as uid:gid, not 'root'")
    assert not world.calls, world.report()


@pytest.mark.parametrize(("args", "user"), [
    pytest.param(["--as-me"], None, id="--as-me"),
    pytest.param(["--as", "{me}"], None, id="--as"),
    pytest.param(["-u", "0:0"], "0:0", id="-u, as typed"),
])
def test_exec_takes_the_user_as_numbers(world, args, user):
    args = [my_name() if a == "{me}" else a for a in args]
    when_dockscreen(world, "exec", *args, "some-container", "id")
    call = then_handed_off(world, "some-container", "id")
    assert f"--user={user or me_user()}" in call.argv or ["-u", user] == call.argv[1:3], world.report()


@pytest.mark.parametrize("args", [
    pytest.param(["-u0:0"], id="-u with its value"),
    pytest.param(["-itu", "0:0"], id="-u in a cluster"),
    pytest.param(["-it", "-e", "A=1", "-u", "0:0"], id="-u after other options"),
    pytest.param(["-u", "0:0", "--"], id="-- before the container"),
])
def test_exec_reads_the_user_in_every_form(world, args):
    when_dockscreen(world, "exec", *args, "some-container", "id")
    call = then_handed_off(world, "some-container", "id")
    assert call.argv[1:-2] == args, world.report()


@pytest.mark.parametrize(("args", "user"), [
    pytest.param(["--user", "root"], "root", id="a name"),
    pytest.param(["--user", "1000"], "1000", id="a uid without a group"),
    pytest.param(["-itu", "root"], "root", id="a name in a cluster"),
    pytest.param(["-uroot"], "root", id="a name with -u"),
])
def test_exec_refuses_a_user_it_cannot_pass_on_as_numbers(world, args, user):
    when_dockscreen(world, "exec", *args, "some-container", "id")
    then_status(world, 1)
    then_said(world, f"--user takes numeric ids as uid:gid, not '{user}'")
    then_nothing_handed_off(world)


def test_exec_without_a_container_is_left_to_docker(world):
    when_dockscreen(world, "exec", "-it")
    then_handed_off(world, "exec", "-it")


def test_containers_after_a_double_dash_are_checked_too(world):
    container = given_container(world, given_image(world, ALPINE), "true")
    when_dockscreen(world, "start", "-a", "--", container)
    then_refused(world, f"{container}: cannot change the user")
    then_nothing_handed_off(world)


def test_create_resolves_a_user_name_and_leaves_what_it_cannot_read_to_docker(world):
    given_image(world, ALPINE)
    name = my_name()
    when_dockscreen(world, "create", "--as", name, "--label=dockscreen-e2e=1", ALPINE, "true")
    then_status(world, 0)
    then_said(world, f"Resolving user {name} to uid ")
    created = [c.created for c in world.calls if c.created]
    assert then_container(world, created[0])["Config"]["User"] == me_user()

    # an option without its value: docker says what is wrong
    when_dockscreen(world, "create", "--name")
    expected = ["create", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--name"]
    assert [c.argv for c in world.calls] == [expected], world.report()
    assert world.result.status != 0, world.report()
