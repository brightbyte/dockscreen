"""Feature: `docker run` starts the container it checked, as a user decided from the image, pinned as
numbers

Rules (docker_run, runargs, rules.userrules):
- run becomes create, inspect, check, start: the daemon reads the command line, and dockscreen checks the
  container it created;
- with no user on the command line the image's user is decided as for compose: the default user instead
  of root (with HOME set unless the command line sets one), the image's own user if the id rules accept it
  with the container's mounts, a user from the config file for an image pulled from its repository;
- whatever is decided is pinned: the container is created again with --user=uid:gid;
- a user on the command line is trusted, but taken as numbers only, or as a name of this host (--as) or the
  caller (--as-me, which also allows the caller's ids);
- every container gets --cap-drop=ALL and --security-opt=no-new-privileges:true, which the command line can
  override;
- a daemon that may not be this host's is refused.
"""

import pytest
from realdocker import ALPINE, NGINX_UNPRIVILEGED, require, user_exists
from steps import (
    given_config,
    given_env,
    given_image,
    given_image_section,
    given_outside_dir,
    given_service,
    home_of,
    me_user,
    my_ids,
    my_name,
    then_container,
    then_failed,
    then_handed_off,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_runs_hardened,
    then_said,
    then_started_container,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e

REMOTE = "the daemon is not the default local one; ids and paths cannot be checked"


def test_a_root_image_starts_as_the_default_user_with_a_home_of_its_own(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "--rm", ALPINE, "id")
    then_passed(world)
    then_said(world, "running as 65534:65534 instead of root", "added --cap-drop=ALL "
                     "--security-opt=no-new-privileges:true")
    container = then_started_container(world)
    assert container["Config"]["User"] == "65534:65534"
    assert home_of(container["Config"]["Env"]) == "/tmp"
    assert container["Config"]["Cmd"] == ["id"]
    then_runs_hardened(world, container)
    # the first container, created to be looked at, is gone
    created = [c.created for c in world.calls if c.created]
    assert len(created) == 2 and world.docker("container", "inspect", created[0]).status != 0, world.report()


def test_a_home_the_command_line_sets_is_kept(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "-e", "HOME=/work", ALPINE, "id")
    then_passed(world)
    assert home_of(then_started_container(world)["Config"]["Env"]) == "/work"


def test_how_docker_start_is_called_follows_the_run_options(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "-d", "-i", "--detach-keys=ctrl-x", ALPINE, "cat")
    then_passed(world)
    call = then_handed_off(world)
    assert call.argv[:-1] == ["start", "--interactive", "--detach-keys=ctrl-x", "--"], world.report()

    when_dockscreen(world, "container", "run", ALPINE, "id")
    assert then_handed_off(world).argv[:-1] == ["start", "--attach", "--"], world.report()


def test_an_image_that_runs_as_the_caller_is_refused(world, own_ids_image):
    when_dockscreen(world, "run", own_ids_image)
    then_refused(world, f"the image's uid {my_ids()[0]} is yours; pass --as-me to run as you")
    then_nothing_handed_off(world)
    assert all(world.docker("container", "inspect", c).status != 0 for c in world.containers), world.report()

    when_dockscreen(world, "run", "--as-me", own_ids_image)
    then_passed(world)
    assert then_started_container(world)["Config"]["User"] == me_user()


def test_an_image_user_that_is_a_local_account_is_refused_unless_the_config_file_sets_it(world):
    require(user_exists(101), "this host has no user 101, which nginx-unprivileged runs as")
    given_image(world, NGINX_UNPRIVILEGED)
    when_dockscreen(world, "run", NGINX_UNPRIVILEGED)
    then_refused(world, "the image's uid 101 exists on this host")
    then_nothing_handed_off(world)

    given_image_section(world, "nginxinc/nginx-unprivileged", 'user = "65533:65533"')
    when_dockscreen(world, "run", NGINX_UNPRIVILEGED)
    then_passed(world)
    assert then_started_container(world)["Config"]["User"] == "65533:65533"


def test_with_a_host_mount_an_image_user_must_be_an_allowed_id(world):
    given_image(world, NGINX_UNPRIVILEGED)
    require(not user_exists(101), "this host has a user 101, which is refused with or without mounts")
    site = given_outside_dir(world, "site")
    when_dockscreen(world, "run", NGINX_UNPRIVILEGED)
    then_passed(world)
    when_dockscreen(world, "run", "-v", f"{site}:/usr/share/nginx/html:ro", NGINX_UNPRIVILEGED)
    then_refused(world, "the image's uid 101 is not in the nobody range 65530-65534",
                 "and there are host mounts")


@pytest.mark.parametrize("user_args", [["--user", "0:0"], ["-u0:0"], ["-itu", "0:0"], ["--user=0:0"]])
def test_a_numeric_user_on_the_command_line_is_trusted(world, user_args):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", *user_args, ALPINE, "id")
    then_passed(world)
    container = then_started_container(world)
    assert container["Config"]["User"] == "0:0"
    then_runs_hardened(world, container)


def test_as_and_as_me_are_resolved_on_this_host(world):
    name = my_name()
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "--as", name, ALPINE, "id")
    then_passed(world)
    then_said(world, f"Resolving user {name} to uid {my_ids()[0]}, gid {my_ids()[1]}")
    assert then_started_container(world)["Config"]["User"] == me_user()

    when_dockscreen(world, "run", "--as-me", ALPINE, "id")
    then_passed(world)
    assert then_started_container(world)["Config"]["User"] == me_user()

    when_dockscreen(world, "run", f"--as={name}", ALPINE, "id")
    then_passed(world)
    assert then_started_container(world)["Config"]["User"] == me_user()


@pytest.mark.parametrize(("user_args", "problem"), [
    pytest.param(["--user", "root"], "--user takes numeric ids as uid:gid, not 'root'; --as NAME runs as a "
                                     "local user, --as-me as yourself", id="a name"),
    pytest.param(["-u", "1000"], "not '1000'; give the group too, as uid:gid", id="a uid without a group"),
    pytest.param(["--as", "dockscreen-e2e-nobody"],
                 "user 'dockscreen-e2e-nobody' does not exist on this host",
                 id="an unknown name"),
])
def test_a_user_that_cannot_be_passed_on_as_numbers_is_refused(world, user_args, problem):
    when_dockscreen(world, "run", *user_args, ALPINE, "id")
    then_refused(world, problem)
    then_nothing_handed_off(world)
    assert not [c for c in world.calls if c.argv[:1] == ["create"]], world.report()


def test_the_defaults_can_be_overridden_on_the_command_line(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "--cap-add=NET_BIND_SERVICE", ALPINE, "id")
    then_passed(world)
    added = then_started_container(world)["HostConfig"]["CapAdd"]
    assert [c.removeprefix("CAP_") for c in added] == ["NET_BIND_SERVICE"], world.report()


def test_an_image_that_is_not_there_fails_with_dockers_status(world):
    when_dockscreen(world, "run", "--pull=never", "dockscreen-e2e/absent:1")
    then_failed(world, "No such image: dockscreen-e2e/absent:1",
                "docker could not create a container for dockscreen-e2e/absent:1", status=1)
    then_nothing_handed_off(world)


def test_a_command_line_that_cannot_be_read_is_refused(world):
    when_dockscreen(world, "run", "--name")
    then_refused(world, "cannot read the command line: --name needs a value")
    then_nothing_handed_off(world)


@pytest.mark.parametrize(("global_args", "env"), [
    pytest.param(["-H", "tcp://192.0.2.1:2375"], {}, id="-H"),
    pytest.param(["--context", "dockscreen-e2e-remote"], {}, id="--context"),
    pytest.param([], {"DOCKER_HOST": "ssh://192.0.2.1"}, id="DOCKER_HOST"),
    pytest.param([], {"DOCKER_CONTEXT": "dockscreen-e2e-remote"}, id="DOCKER_CONTEXT"),
])
def test_a_daemon_that_may_not_be_this_hosts_is_refused(world, global_args, env):
    given_env(world, **env)
    when_dockscreen(world, *global_args, "run", ALPINE)
    then_refused(world, REMOTE)
    then_nothing_handed_off(world)


def test_run_without_arguments_is_left_to_docker(world):
    when_dockscreen(world, "run")
    then_status(world, 0)
    then_handed_off(world, "run")


@pytest.mark.parametrize(("options", "start"), [
    pytest.param(["--detach"], ["start", "--"], id="--detach"),
    pytest.param(["--detach=false"], ["start", "--attach", "--"], id="--detach=false"),
    pytest.param(["--sig-proxy=false"], ["start", "--attach", "--"], id="--sig-proxy"),
    pytest.param(["-a", "stdout"], ["start", "--attach", "--"], id="-a"),
    pytest.param(["-astdout"], ["start", "--attach", "--"], id="-a with its value"),
    pytest.param(["--attach", "stdout"], ["start", "--attach", "--"], id="--attach"),
    pytest.param(["--detach-keys", "ctrl-x", "-d"], ["start", "--detach-keys=ctrl-x", "--"],
                 id="--detach-keys"),
    pytest.param(["-e", "A=1", "--"], ["start", "--attach", "--"], id="-- before the image"),
])
def test_the_options_only_run_has_are_read_before_the_image(world, options, start):
    given_image(world, ALPINE)
    when_dockscreen(world, "run", *options, ALPINE, "id")
    then_passed(world)
    call = then_handed_off(world)
    assert call.argv[:-1] == start, world.report()
    container = then_container(world, call.last)
    assert container["Config"]["Cmd"] == ["id"] and container["Config"]["User"] == "65534:65534"


def test_options_without_an_image_are_refused(world):
    when_dockscreen(world, "run", "-d", "--rm")
    then_refused(world, "cannot read the command line: no image found in the command line")
    then_nothing_handed_off(world)


def test_an_option_dockscreen_does_not_know_fails_closed(world):
    # dockscreen does not know that --cpu-count takes a value, so it reads 2 as the image; on Linux, docker
    # refuses the option, and nothing is assessed or handed off on the misreading
    given_image(world, ALPINE)
    when_dockscreen(world, "run", "--cpu-count", "2", ALPINE, "id")
    then_failed(world, "docker could not create a container for 2", status=1)
    then_nothing_handed_off(world)


def test_without_a_default_home_home_is_left_as_the_image_has_it(world):
    given_image(world, ALPINE)
    given_config(world, "default_home = ''")
    when_dockscreen(world, "run", ALPINE, "id")
    then_passed(world)
    container = then_started_container(world)
    assert container["Config"]["User"] == "65534:65534"
    assert home_of(container["Config"]["Env"]) is None


@pytest.mark.parametrize("args", [["run", ALPINE], ["ps"], ["compose", "up"], ["compose", "audit"]])
def test_a_configured_docker_that_does_not_exist_stops_dockscreen(world, args):
    given_service(world, "app")
    world.config_text = "docker = '/nonexistent/docker'\n"
    when_dockscreen(world, *args)
    then_said(world, "'docker' not found in PATH")
    assert world.result.status in (1, 3), world.report()
    assert not world.calls, world.report()
