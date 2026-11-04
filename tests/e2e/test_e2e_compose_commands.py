"""Feature: every compose command that starts or builds something is screened, and the rest pass on

Rules (docker_compose, ComposeCommand and the compose commands):
- up, create, run, scale, watch and alpha get every check, and compose runs the config that was checked;
- run takes a user from the command line, as numbers or as a name of this host (--as, --as-me), and that
  service's image is then not decided; --as-me before the subcommand is refused;
- with --strict-screen, run judges the service as its options change it (--user, -v, --cap-add,
  --cap-drop, --env-from-file); without it, the command line is trusted;
- build and bake get the checks of what a build can reach: sources inside the project, no host network,
  no privileged build, no SSH agent, no x- keys that buildx bake reads;
- exec takes a user from the command line, as for run, and checks nothing else;
- the commands on the project's containers (down, stop, ...) check only its name (test_e2e_compose_project);
- everything else passes on to compose unchanged.
"""

import pytest
from realdocker import ALPINE
from steps import (
    given_file,
    given_image,
    given_image_section,
    given_service,
    me_user,
    my_name,
    then_generated_service,
    then_handed_off,
    then_handed_off_unchanged,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("sub", [
    pytest.param(["up"], id="up"),
    pytest.param(["create"], id="create"),
    pytest.param(["run", "app", "true"], id="run"),
    pytest.param(["scale", "app=2"], id="scale"),
    pytest.param(["watch"], id="watch"),
    pytest.param(["alpha", "watch"], id="alpha"),
])
def test_a_command_that_starts_containers_is_refused_for_a_project_that_reaches_too_far(world, sub):
    given_service(world, "app", privileged=True)
    when_dockscreen(world, "compose", *sub)
    then_refused(world, "service app: privileged is not allowed")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("sub", [
    pytest.param(["up", "-d"], id="up"),
    pytest.param(["create"], id="create"),
    pytest.param(["run", "--rm", "app", "true"], id="run"),
    pytest.param(["scale", "app=2"], id="scale"),
])
def test_a_command_that_starts_containers_runs_the_checked_config(world, sub):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", *sub)
    then_passed(world)
    then_handed_off(world, *sub)
    assert then_generated_service(world)["user"] == "65534:65534"


@pytest.mark.parametrize(("user_args", "user"), [
    pytest.param(["-u", "20000:20000"], "20000:20000", id="-u"),
    pytest.param(["--user=20000:20000"], "20000:20000", id="--user"),
    pytest.param(["--as-me"], None, id="--as-me"),
])
def test_run_takes_the_user_from_the_command_line_and_does_not_decide_the_image(world, user_args, user):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "run", *user_args, "app", "id")
    then_passed(world)
    call = then_handed_off(world, "app", "id")
    given = f"--user={user or me_user()}" in call.argv or call.argv[call.argv.index("-u") + 1] == user
    assert given, world.report()
    # the service runs as the default user should the command line's user be lost on the way
    service = call.compose_file["services"]["app"]
    assert service["user"] == "65534:65534" and "pull_policy" not in service


def test_run_resolves_a_user_name_on_this_host(world):
    name = my_name()
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "run", "--as", name, "app", "id")
    then_passed(world)
    then_said(world, f"Resolving user {name} to uid ")
    assert f"--user={me_user()}" in then_handed_off(world, "app", "id").argv


@pytest.mark.parametrize(("user_args", "problem"), [
    pytest.param(["-u", "root"], "--user takes numeric ids as uid:gid, not 'root'", id="a name"),
    pytest.param(["-u", "1000"], "--user takes numeric ids as uid:gid, not '1000'; give the group too",
                 id="a uid without a group"),
    pytest.param(["--as", "dockscreen-e2e-nobody"],
                 "user 'dockscreen-e2e-nobody' does not exist on this host",
                 id="an unknown name"),
    pytest.param(["--as", "0"], "--as takes the name of a local user, not '0'; use --user for ids",
                 id="an id"),
])
def test_run_refuses_a_user_it_cannot_pass_on_as_numbers(world, user_args, problem):
    given_service(world, "app")
    when_dockscreen(world, "compose", "run", *user_args, "app", "id")
    then_refused(world, problem)
    then_nothing_handed_off(world)


def test_run_checks_the_service_it_names_even_behind_a_profile(world):
    given_service(world, "app")
    given_service(world, "debug", profiles=["debug"], cap_add=["SYS_PTRACE"])
    when_dockscreen(world, "compose", "run", "debug", "true")
    then_refused(world, "service debug: cap_add is not allowed")
    then_nothing_handed_off(world)


def test_strict_screening_judges_the_service_as_runs_options_change_it(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "run", "--rm", "-v", "/etc:/e:ro", "app", "true")
    then_passed(world)  # the command line is trusted
    when_dockscreen(world, "--strict-screen", "compose", "run", "--rm", "-v", "/etc:/e:ro", "app", "true")
    then_refused(world, "service app: bind mount '/etc' is outside")


def test_as_me_before_the_subcommand_is_refused(world):
    given_service(world, "app")
    when_dockscreen(world, "compose", "--as-me", "up")
    then_status(world, 2)
    then_said(world, "--as-me goes after run or exec, before the service")
    then_nothing_handed_off(world)


@pytest.mark.parametrize(("build", "problem"), [
    pytest.param({"context": "/etc"}, "build context '/etc' is outside", id="a context outside"),
    pytest.param({"context": ".", "dockerfile": "../Dockerfile"},
                 "build dockerfile '../Dockerfile' is outside", id="a Dockerfile outside"),
    pytest.param({"context": ".", "additional_contexts": {"etc": "/etc"}},
                 "build additional_contexts 'etc': '/etc' is outside", id="a named context outside"),
    pytest.param({"context": ".", "network": "host"}, "build network 'host' is not allowed",
                 id="host network"),
    pytest.param({"context": ".", "privileged": True}, "build privileged is not allowed", id="privileged"),
    pytest.param({"context": ".", "ssh": ["default"]}, "build ssh forwards your SSH agent and is not allowed",
                 id="the SSH agent"),
])
@pytest.mark.parametrize("sub", ["build", "bake", "up"])
def test_a_build_that_reaches_the_host_is_refused(world, build, problem, sub):
    given_file(world, "Dockerfile", f"FROM {ALPINE}\n")
    given_service(world, "app", build=build)
    when_dockscreen(world, "compose", sub)
    then_refused(world, f"service app: {problem}")
    then_nothing_handed_off(world)
    assert not [c for c in world.calls if "build" in c.argv], world.report()


def test_compose_drops_x_bake_from_a_build_so_its_output_is_never_written(world):
    # buildx bake reads x-bake from a compose file (test_e2e_docker_bake); compose's own build does not
    given_image(world, ALPINE)
    out = world.base / "out"
    given_file(world, "Dockerfile", f"FROM {ALPINE}\n")
    given_service(world, "app", build={"context": ".", "x-bake": {"output": [f"type=local,dest={out}"]}})
    when_dockscreen(world, "compose", "build")
    world.docker("image", "rm", f"{world.name}-app")
    then_passed(world)
    assert not out.exists(), world.report()


def test_a_build_secret_from_outside_the_project_is_refused(world):
    given_file(world, "Dockerfile", f"FROM {ALPINE}\n")
    given_service(world, "app", build={"context": ".", "secrets": ["key"]})
    world.compose["secrets"] = {"key": {"file": "/etc/hostname"}}
    when_dockscreen(world, "compose", "build")
    then_refused(world, f"secrets key: file '/etc/hostname' is outside {world.project_dir}")


def test_build_checks_only_what_a_build_can_reach(world):
    given_file(world, "Dockerfile", f"FROM {ALPINE}\n")
    given_service(world, "app", build={"context": "."}, privileged=True)  # up would refuse this
    when_dockscreen(world, "compose", "bake", "--print")
    then_passed(world)
    then_handed_off_unchanged(world, "compose", "bake", "--print")


@pytest.mark.parametrize(("args", "user"), [
    pytest.param(["--as-me"], None, id="--as-me"),
    pytest.param(["-u", "0:0"], "0:0", id="-u, as typed"),
])
def test_exec_takes_the_user_as_numbers(world, args, user):
    given_service(world, "app")
    when_dockscreen(world, "compose", "exec", *args, "app", "id")
    call = then_handed_off(world, "app", "id")
    assert call.argv[:2] == ["compose", "exec"], world.report()
    assert f"--user={user or me_user()}" in call.argv or call.argv[2:4] == ["-u", user], world.report()


def test_exec_refuses_a_user_name(world):
    given_service(world, "app")
    when_dockscreen(world, "compose", "exec", "--user", "root", "app", "id")
    then_status(world, 1)
    then_said(world, "--user takes numeric ids as uid:gid, not 'root'")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("args", [["ps"], ["logs", "app"], ["ls"], ["config", "--services"]])
def test_commands_that_start_nothing_pass_on_unchanged(world, args):
    given_service(world, "app", privileged=True)
    when_dockscreen(world, "compose", *args)
    assert [c.argv for c in world.calls] == [["compose", *args]], world.report()
    assert "denied" not in world.output


def test_build_sources_that_are_not_host_paths_are_not_checked(world):
    given_service(world, "app", build={"context": "https://github.com/docker-library/hello-world.git",
                                       "additional_contexts": {"base": "docker-image://alpine:3.20"}})
    given_service(world, "db", image=ALPINE)  # no build, nothing to check
    when_dockscreen(world, "compose", "bake")
    then_passed(world)
    then_handed_off(world, "bake")


@pytest.mark.parametrize("pull", [["--pull", "always"], ["--pull=always"]])
def test_up_pulls_as_the_command_line_says(world, pull):
    given_image(world, ALPINE)
    given_service(world, "app", pull_policy="never")
    when_dockscreen(world, "compose", "up", *pull)
    then_passed(world)
    assert [c.argv for c in world.calls if "pull" in c.argv], world.report()
    then_handed_off(world, "up", *pull)


def test_a_service_behind_a_profile_whose_image_is_not_there_gets_the_default_user(world):
    given_image(world, ALPINE)
    given_image_section(world, "dockscreen-e2e/absent", 'user = "65533:65533"')
    given_service(world, "app")
    given_service(world, "debug", image="dockscreen-e2e/absent:1", profiles=["debug"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world, "debug")["user"] == "65534:65534"
