"""Feature: `dockscreen compose audit` says what `up` would do, on projects as they are found in the wild

Rules (compose_audit):
- the audit runs the checks of up, pulls and builds as up would, and starts nothing;
- the verdict is the exit status: 0 passed, 1 refused, 3 failed (the config could not be read, an image
  could not be pulled, built or looked at), 2 a command line that cannot be read;
- the report says what dockscreen changes (defaults, users), which variables the shell passes in, and
  that the harden subcommand fixes what it can;
- --brief prints the verdict alone, on one line.

webapp: an app built from a Dockerfile with the caller's ids, a cache and a web server from pulled images,
a debug service behind a profile, and an override for debugging that asks for too much.
monitoring: cAdvisor and the node exporter, which read the host as their documentation sets them up.
"""

import json
import re

import pytest
from realdocker import ALPINE, NGINX, REDIS, WEBAPP_APP
from steps import (
    given_env,
    given_example_project,
    given_file,
    given_image,
    given_outside_dir,
    given_project_section,
    given_service,
    given_symlink,
    me_user,
    then_failed,
    then_nothing_acquired,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def webapp(world, ordinary_ids):
    """Given the webapp, and the images it pulls: a registry out of reach skips the scenario."""
    for image in (ALPINE, REDIS, NGINX):
        given_image(world, image)
    given_example_project(world, "webapp")


def test_the_webapp_passes_with_allow_me_and_says_what_it_changes(world, webapp):
    given_env(world, TZ="Europe/Berlin")
    when_dockscreen(world, "--allow-me", "compose", "audit")
    then_passed(world)
    then_said(world,
              f"service app: no user set; image {WEBAPP_APP} runs as uid {me_user().split(':')[0]} ",
              "service cache: no user set; image ", "service web: no user set; image ",
              "; running as 65534:65534 instead of root",
              "service mailpit: no user set and not started by default",
              "service app: environment variables taken from your shell: TZ",
              "cap_drop", "no-new-privileges",
              "the harden subcommand prints a compose override file with these fixes")
    then_nothing_handed_off(world)


def test_an_image_that_runs_as_the_caller_is_refused_without_allow_me(world, webapp):
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"service app: image {WEBAPP_APP}: the image's uid {me_user().split(':')[0]} is "
                        "yours; --allow-me allows it")


def test_a_static_dir_from_dotenv_outside_the_project_is_refused_before_anything_is_pulled(world):
    given_example_project(world, "webapp")
    given_file(world, ".env", "STATIC_DIR=/etc\n")
    when_dockscreen(world, "--allow-me", "compose", "audit")
    then_refused(world, "service web: bind mount '/etc' is outside")
    then_said(world, "nothing was pulled or built")
    then_nothing_acquired(world)


def test_a_symlink_in_the_example_project_is_followed_out_of_it(world):
    given_example_project(world, "webapp")
    (world.project_dir / "static" / "index.html").unlink()
    (world.project_dir / "static").rmdir()
    given_symlink(world, "static", "/etc")
    when_dockscreen(world, "--allow-me", "compose", "audit")
    then_refused(world)
    assert re.search(r"service web: bind mount '[^']*static' is outside", world.output), world.report()


def test_mount_dirs_of_the_project_allow_a_static_dir_outside_it(world, webapp):
    site = given_outside_dir(world, "site")
    given_env(world, STATIC_DIR=str(site))
    when_dockscreen(world, "--allow-me", "compose", "audit")
    then_refused(world, f"service web: bind mount '{site}' is outside",
                 "add a directory that contains it to mount_dirs under [projects.")
    given_project_section(world, f"mount_dirs = ['{site}']")
    when_dockscreen(world, "--allow-me", "compose", "audit")
    then_passed(world)


def test_an_image_section_sets_the_user_of_an_image_pulled_from_that_repository(world, webapp):
    world.config += '[images."redis"]\nuser = "999:999"\n'
    when_dockscreen(world, "--allow-me", "compose", "audit")
    then_passed(world)
    then_said(world, f"service cache: no user set; image {REDIS} runs as 999:999,",
              "the user the config file sets for it")


def test_the_debug_override_is_refused_for_each_way_it_reaches_beyond_the_container(world):
    given_example_project(world, "webapp")
    when_dockscreen(world, "--allow-me", "compose", "-f", "compose.yaml", "-f", "compose.debug.yaml", "audit")
    then_refused(world, "service app: cap_add is not allowed",
                 "service app: security_opt 'seccomp=unconfined' is not allowed",
                 "service app: bind mount '/var/run/docker.sock' is outside",
                 "nothing was pulled or built")


def test_the_monitoring_stack_is_refused_for_each_way_it_reaches_the_host(world):
    given_example_project(world, "monitoring")
    when_dockscreen(world, "compose", "audit")
    then_refused(world,
                 "service cadvisor: privileged is not allowed",
                 "service cadvisor: devices is not allowed",
                 "service cadvisor: bind mount '/' is outside",
                 "service cadvisor: bind mount '/sys' is outside",
                 "service node-exporter: pid: host shares a namespace outside the project",
                 "service node-exporter: network_mode: host shares a namespace outside the project",
                 "service node-exporter: bind mount '/' is outside",
                 "nothing was pulled or built",
                 "harden")


def test_brief_prints_only_the_verdict_with_the_first_reason(world):
    given_example_project(world, "monitoring")
    when_dockscreen(world, "compose", "audit", "--brief")
    then_status(world, 1)
    assert world.result.stdout.count("\n") == 1, world.report()
    assert re.fullmatch(r"⊖ denied by audit: service \S+: .* \(\+\d+ more\)", world.result.last_line), \
        world.report()


def test_the_audit_fails_when_compose_cannot_read_the_project(world):
    given_file(world, "compose.yaml", json.dumps({"services": {"app": {"image": ALPINE, "volumes": 3}}}))
    when_dockscreen(world, "compose", "audit")
    then_failed(world, "docker compose config failed")


def test_the_audit_takes_no_arguments_but_brief(world):
    given_service(world, "app")
    when_dockscreen(world, "compose", "audit", "app")
    then_status(world, 2)
    then_said(world, "usage: dockscreen compose [compose options] audit [--brief]")


def test_a_project_refused_before_its_config_is_read_is_refused_by_the_audit(world):
    given_service(world, "app")
    given_file(world, ".env", "COMPOSE_FILE=elsewhere.yaml\n")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR")


def test_brief_prints_only_the_verdict_when_it_passes(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "audit", "--brief")
    then_status(world, 0)
    assert world.result.stdout == "✔ audit passed\n", world.report()


def test_a_service_that_needs_nothing_changed_gets_no_hint_at_harden(world):
    given_image(world, ALPINE)
    given_service(world, "app", user="65534:65534", cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    when_dockscreen(world, "compose", "audit")
    then_passed(world)
    assert "harden" not in world.output and "added cap_drop" not in world.output, world.report()
