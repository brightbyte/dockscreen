"""Feature: `dockscreen compose harden` prints a compose override that fixes what has a safe fix

Rules (compose_harden):
- privileges and the host's namespaces are removed (`!reset`), security options and capabilities replaced
  (`!override`), mount sources outside the project replaced by placeholders to edit;
- a user the rules refuse, set by the service or chosen by its image, becomes `${UID}:${GID}`, which needs
  --allow-me to run;
- what has no safe fix (volumes, networks, secrets, build contexts, env files, unknown keys) is listed as
  comments, and the exit status is 1;
- pull_policy is never written into the override;
- text from the project is escaped, so it cannot add lines to the override.
"""

import pytest
from realdocker import ALPINE, NGINX, REDIS
from steps import (
    given_compose,
    given_example_project,
    given_file,
    given_image,
    given_service,
    given_symlink,
    then_nothing_acquired,
    then_nothing_handed_off,
    then_passed,
    then_said,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e

DEBUG = ("compose", "-f", "compose.yaml", "-f", "compose.debug.yaml")


def test_harden_fixes_the_debug_override_so_that_the_audit_passes(world, ordinary_ids):
    for image in (ALPINE, REDIS, NGINX):
        given_image(world, image)
    given_example_project(world, "webapp")
    when_dockscreen(world, *DEBUG, "harden")
    then_status(world, 0)
    patch = world.result.stdout
    assert "cap_add: !reset null" in patch
    assert "security_opt: !override [" in patch and "seccomp" not in patch
    assert "mount source /var/run/docker.sock was replaced by the placeholder ./VAR_RUN_DOCKER.SOCK" in patch
    assert "user:" not in patch  # the app runs as you, which harden allows as --allow-me would
    assert "pull_policy" not in patch
    then_nothing_handed_off(world)

    given_file(world, "compose.harden.yaml", patch)
    when_dockscreen(world, "--allow-me", *DEBUG, "-f", "compose.harden.yaml", "audit")
    then_passed(world)


def test_harden_removes_privileges_and_lists_what_it_cannot_fix(world):
    given_service(world, "app", privileged=True, pid="host", network_mode="host", cap_add=["SYS_ADMIN"],
                  devices=["/dev/kmsg:/dev/kmsg"], volumes=["/:/rootfs:ro", "data:/data"])
    given_compose(world, "volumes", {"data": {"external": True}})
    when_dockscreen(world, "compose", "harden")
    then_status(world, 1)
    patch = world.result.stdout
    for key in ("privileged", "pid", "network_mode", "cap_add", "devices"):
        assert f"    {key}: !reset null" in patch, world.report()
    assert "# edit: service app: mount source / was replaced by the placeholder" in patch, world.report()
    assert "# not fixed: volume data: external resources are not allowed" in patch, world.report()
    then_said(world, "cannot fix automatically: volume data: external resources are not allowed",
              "nothing was pulled or built")
    then_nothing_acquired(world)


@pytest.mark.parametrize("user", ["0:0", "root"])
def test_harden_replaces_a_user_the_project_may_not_choose(world, user):
    given_image(world, ALPINE)
    given_service(world, "app", user=user)
    when_dockscreen(world, "compose", "harden")
    then_status(world, 0)
    patch = world.result.stdout
    assert 'user: "${UID}:${GID}"' in patch
    assert "dockscreen allows that only with --allow-me" in patch


def test_harden_sets_a_user_where_the_image_chose_one_that_is_refused(world, stranger_image):
    image, _ = stranger_image
    given_file(world, "src/index.html")
    given_service(world, "app", image=image, volumes=["./src:/app/src"])
    when_dockscreen(world, "compose", "harden")
    then_status(world, 0)
    patch = world.result.stdout
    note = f"service app: image {image} chose a user that is not acceptable, so user is set explicitly"
    assert note in patch, world.report()
    assert 'user: "${UID}:${GID}"' in patch


def test_harden_escapes_what_the_project_names(world):
    source = "/tmp/dockscreen-e2e\nservices: {evil: {privileged: true}}"
    given_service(world, "app", volumes=[{"type": "bind", "source": source, "target": "/x"}])
    when_dockscreen(world, "compose", "harden")
    patch = world.result.stdout
    assert "\nservices: {evil" not in patch, world.report()
    assert "mount source /tmp/dockscreen-e2e\\x0aservices: {evil" in patch, world.report()


def test_harden_refuses_a_daemon_that_may_not_be_this_hosts(world):
    given_service(world, "app")
    world.env["DOCKER_HOST"] = "tcp://192.0.2.1:2375"
    when_dockscreen(world, "compose", "harden")
    then_status(world, 1)
    then_said(world, "the daemon is not the default local one")


def test_harden_refuses_a_project_refused_before_its_config_is_read(world):
    given_service(world, "app")
    given_file(world, ".env", "COMPOSE_FILE=elsewhere.yaml\n")
    when_dockscreen(world, "compose", "harden")
    then_status(world, 1)
    then_said(world, "sets COMPOSE_FILE or COMPOSE_PATH_SEPARATOR")
    assert world.result.stdout == "", world.report()


def test_harden_lists_an_image_it_cannot_look_at(world):
    given_service(world, "app", image="dockscreen-e2e/absent:1", pull_policy="never")
    when_dockscreen(world, "compose", "harden")
    then_status(world, 1)
    assert "# not fixed: service app: image dockscreen-e2e/absent:1: the image is not available locally" \
        in world.result.stdout, world.report()


def test_harden_drops_the_volumes_of_other_containers(world):
    given_image(world, ALPINE)
    given_service(world, "app", volumes_from=["container:someone-else"])
    when_dockscreen(world, "compose", "harden")
    then_status(world, 0)
    assert "volumes_from: !reset null" in world.result.stdout, world.report()


def test_harden_keeps_the_volumes_of_the_projects_own_services(world):
    given_image(world, ALPINE)
    given_service(world, "db")
    given_service(world, "app", volumes_from=["db", "container:someone-else"])
    when_dockscreen(world, "compose", "harden")
    then_status(world, 0)
    assert "container:someone-else" not in world.result.stdout, world.report()
    assert 'volumes_from: !override ["db"]' in world.result.stdout, world.report()


def test_harden_replaces_a_mount_that_a_symlink_takes_out_of_the_project(world):
    given_image(world, ALPINE)
    given_symlink(world, "data", "/etc")
    given_service(world, "app", volumes=["./data:/data:ro"])
    when_dockscreen(world, "compose", "harden")
    then_status(world, 0)
    assert "was replaced by the placeholder ./DATA," in world.result.stdout, world.report()


def test_harden_of_a_project_that_needs_nothing_writes_no_service(world):
    given_image(world, ALPINE)
    given_service(world, "app", user="65534:65534")
    when_dockscreen(world, "compose", "harden")
    then_status(world, 0)
    assert world.result.stdout.endswith("services: {}\n"), world.report()
