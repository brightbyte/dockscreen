"""Feature: dockscreen checks the project compose would run, under a name that is its own

Rules (inspect, composeproject):
- the project directory is found as compose finds it, and a project that could send compose elsewhere is
  refused: COMPOSE_FILE in a .env; a compose file from stdin cannot be screened;
- a project directory that is or contains a sensitive path (/, the home directory, the config file) is
  refused, because everything in it can be mounted;
- the project's name decides which containers, volumes and networks compose uses and removes, so a name
  that containers made from another directory have is refused; a name the caller gives is not checked;
- a daemon that may not be this host's is refused, because ids and paths cannot be checked there;
- compose runs the config that was checked, from a generated file, with the project's directory and name
  pinned and the caller's -f, -p and --project-directory replaced.
"""

import json

import pytest
from realdocker import ALPINE
from steps import (
    given_env,
    given_example_project,
    given_file,
    given_image,
    given_outside_dir,
    given_project_container,
    given_service,
    then_failed,
    then_handed_off,
    then_nothing_acquired,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e

REMOTE = "the daemon is not the default local one; ids and paths cannot be checked"


@pytest.mark.parametrize("line", ["COMPOSE_FILE=elsewhere/compose.yaml", "export COMPOSE_PATH_SEPARATOR=;"])
def test_a_dotenv_that_points_compose_elsewhere_is_refused(world, line):
    given_service(world, "app")
    given_file(world, ".env", f"{line}\n")
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"{world.project_dir / '.env'} sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR")
    then_nothing_handed_off(world)


def test_an_env_file_given_on_the_command_line_is_checked_the_same_way(world):
    given_service(world, "app")
    given_file(world, "other.env", "COMPOSE_FILE=x.yaml\n")
    when_dockscreen(world, "compose", "--env-file", "other.env", "up")
    then_refused(world, "other.env sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR")


def test_a_compose_file_from_stdin_cannot_be_screened(world):
    when_dockscreen(world, "compose", "-f", "-", "up")
    then_failed(world, "a compose file read from stdin cannot be inspected", status=1)
    then_nothing_handed_off(world)


def test_a_project_directory_that_contains_the_root_is_refused(world):
    given_service(world, "app")
    when_dockscreen(world, "compose", "--project-directory", "/", "up")
    then_refused(world, "the project directory / contains /;",
                 "move the compose file into a directory of its own")
    then_nothing_handed_off(world)


def test_a_project_directory_that_contains_the_config_file_is_refused(world):
    world.cwd = world.config_file.parent.parent  # the config home
    project = {"name": world.name, "services": {"app": {"image": ALPINE}}}
    (world.cwd / "compose.yaml").write_text(json.dumps(project))
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"contains {world.config_file}")
    then_nothing_handed_off(world)


def test_a_project_without_a_compose_file_fails(world):
    when_dockscreen(world, "compose", "audit")
    then_failed(world, "no compose file found")


def test_the_compose_file_is_found_in_a_directory_above(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    world.cwd = given_file(world, "sub/dir/.keep").parent
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    call = then_handed_off(world, "up")
    assert call.argv[call.argv.index("--project-directory") + 1] == str(world.project_dir)


def test_the_project_directory_follows_the_first_compose_file(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    world.cwd = given_file(world, "../elsewhere/.keep").parent
    when_dockscreen(world, "compose", "-f", str(world.project_dir / "compose.yaml"), "up")
    then_passed(world)
    call = then_handed_off(world, "up")
    assert call.argv[call.argv.index("--project-directory") + 1] == str(world.project_dir)


def test_compose_runs_the_generated_file_alone_with_directory_and_name_pinned(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "-f", "compose.yaml", "--project-directory", ".", "up", "-d")
    then_passed(world)
    call = then_handed_off(world, "up", "-d")
    files = [call.argv[i + 1] for i, a in enumerate(call.argv) if a in ("-f", "--file")]
    assert len(files) == 1 and "/dockscreen-" in files[0], world.report()
    assert call.argv.count("--project-directory") == 1
    assert call.argv[call.argv.index("--project-name") + 1] == world.name
    assert call.compose_file["name"] == world.name


def test_the_callers_other_compose_options_are_kept(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "--progress", "plain", "up")
    then_passed(world)
    call = then_handed_off(world, "up")
    assert call.argv[call.argv.index("--progress") + 1] == "plain", world.report()


def test_a_name_used_by_containers_of_another_directory_is_refused(world):
    given_project_container(world, world.name, "/srv/victim")
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"project name '{world.name}' is used by containers made from '/srv/victim', not "
                        f"from {world.project_dir}")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


def test_a_container_that_does_not_say_where_it_was_made_counts_as_another_directory(world):
    given_project_container(world, world.name, None)
    given_service(world, "app")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "is used by containers made from an unknown directory")


def test_containers_of_the_same_directory_are_the_projects_own(world):
    given_image(world, ALPINE)
    given_project_container(world, world.name, str(world.project_dir))
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_passed(world)


def test_a_name_from_the_projects_dotenv_is_checked(world):
    given_project_container(world, "dse2e-victim-" + world.name[-6:], "/srv/victim")
    given_service(world, "app")
    del world.compose["name"]
    given_file(world, ".env", f"COMPOSE_PROJECT_NAME=dse2e-victim-{world.name[-6:]}\n")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "is used by containers made from '/srv/victim'")


@pytest.mark.parametrize("how", ["-p", "environment"])
def test_a_name_the_caller_chooses_is_not_checked(world, how):
    given_image(world, ALPINE)
    given_project_container(world, world.name, "/srv/victim")
    given_service(world, "app")
    if how == "-p":
        when_dockscreen(world, "compose", "-p", world.name, "up")
    else:
        given_env(world, COMPOSE_PROJECT_NAME=world.name)
        when_dockscreen(world, "compose", "up")
    then_passed(world)


@pytest.mark.parametrize("sub", ["down", "rm", "stop", "kill", "restart", "start", "pause", "unpause"])
def test_commands_on_the_projects_containers_are_refused_under_a_name_that_is_not_its_own(world, sub):
    given_project_container(world, world.name, "/srv/victim")
    given_service(world, "app")
    when_dockscreen(world, "compose", sub)
    then_refused(world, f"project name '{world.name}' is used by containers made from '/srv/victim'")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("sub", ["down", "stop"])
def test_commands_on_the_projects_containers_are_handed_on_under_its_own_name(world, sub):
    given_service(world, "app", privileged=True)  # only the name is checked: up refused this already
    when_dockscreen(world, "compose", sub, "--timeout", "1")
    then_status(world, 0)
    call = then_handed_off(world, sub, "--timeout", "1")
    assert call.argv[:2] == ["compose", sub], world.report()


def test_a_daemon_that_may_not_be_this_hosts_is_refused(world):
    given_service(world, "app")
    given_env(world, DOCKER_HOST="tcp://192.0.2.1:2375")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, REMOTE)
    then_nothing_acquired(world)


def test_the_example_webapp_runs_with_allow_me_as_checked(world, ordinary_ids):
    for image in (ALPINE, "redis:7.4-alpine", "nginx:1.27-alpine"):
        given_image(world, image)
    given_example_project(world, "webapp")
    when_dockscreen(world, "--allow-me", "compose", "up", "-d")
    then_passed(world)
    services = then_handed_off(world, "up", "-d").compose_file["services"]
    assert services["app"]["user"] == f"{ordinary_ids[0]}:{ordinary_ids[1]}"
    assert services["cache"]["user"] == services["web"]["user"] == "65534:65534"
    assert services["mailpit"]["user"] == "65534:65534"  # behind a profile
    for service in services.values():
        assert service["cap_drop"] == ["ALL"] and service["security_opt"] == ["no-new-privileges:true"]
    assert services["web"]["image"].startswith("sha256:")


@pytest.mark.parametrize("name_args", [
    pytest.param(["--project-name={name}"], id="--project-name="),
    pytest.param(["-p{name}"], id="-pNAME"),
    pytest.param(["-p={name}"], id="-p=NAME"),
])
def test_a_name_the_caller_chooses_is_not_checked_however_it_is_spelled(world, name_args):
    given_project_container(world, world.name, "/srv/victim")
    given_service(world, "app")
    when_dockscreen(world, "compose", *[a.format(name=world.name) for a in name_args], "down")
    then_status(world, 0)
    then_handed_off(world, "down")


@pytest.mark.parametrize("file_args", [
    pytest.param(["--file=compose.yaml"], id="--file="),
    pytest.param(["-fcompose.yaml"], id="-fFILE"),
    pytest.param(["-f=compose.yaml"], id="-f=FILE"),
])
def test_the_callers_compose_file_is_replaced_by_the_generated_one_however_it_is_spelled(world, file_args):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", *file_args, "up")
    then_passed(world)
    call = then_handed_off(world, "up")
    assert not [a for a in call.argv if "compose.yaml" in a and "/dockscreen-" not in a], world.report()


def test_compose_file_in_the_callers_environment_selects_the_project(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    world.cwd = given_outside_dir(world)
    given_env(world, COMPOSE_FILE=str(world.project_dir / "compose.yaml"))
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    call = then_handed_off(world, "up")
    assert call.argv[call.argv.index("--project-directory") + 1] == str(world.project_dir)


def test_commands_on_the_containers_leave_a_project_compose_cannot_read_to_compose(world):
    given_service(world, "app")
    given_file(world, ".env", "COMPOSE_FILE=elsewhere.yaml\n")
    when_dockscreen(world, "compose", "down")
    then_status(world, 0)
    then_handed_off(world, "down")


def test_a_project_compose_cannot_read_fails_a_command_that_starts_containers(world):
    given_file(world, "compose.yaml", json.dumps({"services": {"app": {"image": ALPINE, "volumes": 3}}}))
    when_dockscreen(world, "compose", "up")
    then_failed(world, "docker compose config failed", status=1)
    then_nothing_handed_off(world)


@pytest.mark.parametrize("sub", ["build", "bake"])
def test_a_build_of_a_project_that_cannot_be_checked_is_refused(world, sub):
    given_file(world, "compose.yaml", json.dumps({"services": {"app": {"build": ".", "volumes": 3}}}))
    when_dockscreen(world, "compose", sub)
    then_failed(world, "docker compose config failed", status=1)
    given_file(world, "compose.yaml", json.dumps({"services": {"app": {"build": "."}}}))
    given_file(world, ".env", "COMPOSE_FILE=elsewhere.yaml\n")
    when_dockscreen(world, "compose", sub)
    then_refused(world, "sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR")
    then_nothing_handed_off(world)
