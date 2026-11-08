"""Feature: `dockscreen audit` says what `docker run` would do with the same arguments, starting nothing

Rules (docker_run.audit, Policy.check_container):
- the container is created as run would create it, looked at as run would, and removed;
- the verdict is the exit status: 0 passed, 1 refused, 3 failed (the image could not be looked at),
  2 a command line that cannot be read;
- what the command line asks for that a project or an image could not have is pointed out; it fails the
  audit only with --strict-screen, since the command line is trusted;
- --brief prints the verdict alone, on one line.
"""

import pytest
from realdocker import ALPINE, NGINX_UNPRIVILEGED, require, toml_string, user_exists
from steps import (
    FAILED,
    given_config,
    given_image,
    given_outside_dir,
    my_ids,
    my_name,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    then_status,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e

# With docker's containerd image store, RepoDigests lists a digest under every name an image has, so a
# local tag or build passes for having been pulled from that repository (docs/security-review.md).
LOCAL_NAME_PROVES_A_PULL = "a locally tagged or built image counts as pulled from its repository"


def test_a_root_image_runs_as_the_default_user(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "audit", ALPINE)
    then_passed(world)
    then_said(world, f"image {ALPINE}: would run as uid 0 ",
              "; running as 65534:65534 instead of root",
              "docker run would create it again with --user=65534:65534, as numbers",
              "docker run also adds --cap-drop=ALL --security-opt=no-new-privileges:true")
    then_nothing_handed_off(world)
    assert all(world.docker("container", "inspect", c).status != 0 for c in world.containers), world.report()


@pytest.mark.parametrize(("args", "finding"), [
    pytest.param(["--privileged"], "privileged is not allowed", id="--privileged"),
    pytest.param(["--cap-add=SYS_ADMIN"], "cap_add is not allowed", id="--cap-add"),
    pytest.param(["--device=/dev/null"], "devices is not allowed", id="--device"),
    pytest.param(["--device-cgroup-rule=c 1:3 mr"], "device_cgroup_rules is not allowed",
                 id="--device-cgroup-rule"),
    pytest.param(["--cgroup-parent=dockscreen-e2e.slice"], "cgroup_parent is not allowed",
                 id="--cgroup-parent"),
    pytest.param(["--group-add=0"], "group_add is not allowed", id="--group-add"),
    pytest.param(["--security-opt=seccomp=unconfined"], "security_opt 'seccomp=unconfined' is not allowed",
                 id="--security-opt"),
    pytest.param(["--pid=host"], "pid: host shares a namespace outside the project", id="--pid"),
    pytest.param(["--ipc=host"], "ipc: host shares a namespace outside the project", id="--ipc"),
    pytest.param(["--uts=host"], "uts: host shares a namespace outside the project", id="--uts"),
    pytest.param(["--userns=host"], "userns_mode: host shares a namespace outside the project",
                 id="--userns"),
    pytest.param(["--cgroupns=host"], "cgroup: host shares a namespace outside the project", id="--cgroupns"),
    pytest.param(["--network=host"], "network_mode: host shares a namespace outside the project",
                 id="--network"),
    pytest.param(["-v", "/:/host"], "bind mount '/' is outside", id="-v"),
    pytest.param(["--mount", "type=bind,source=/etc,target=/h"], "bind mount '/etc' is outside",
                 id="--mount"),
    pytest.param(["--user=0:0"], "user '0:0': uid 0 is root", id="--user root"),
])
def test_what_the_command_line_asks_for_fails_the_audit_only_when_strict(world, args, finding):
    given_image(world, ALPINE)
    when_dockscreen(world, "audit", *args, ALPINE, "true")
    then_passed(world)
    then_said(world, f"command line: {finding}", "--strict-screen makes them fail the audit")

    when_dockscreen(world, "--strict-screen", "audit", *args, ALPINE, "true")
    then_refused(world, finding)


def test_a_bind_mount_of_the_current_directory_is_no_finding(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "--strict-screen", "audit", "-v", f"{world.cwd}:/work", ALPINE, "true")
    then_passed(world)


def test_volumes_of_another_container_are_a_finding(world):
    given_image(world, ALPINE)
    other = world.docker("create", "--label=dockscreen-e2e=1", ALPINE, "true").stdout.strip()
    world.containers.append(other)
    when_dockscreen(world, "--strict-screen", "audit", "--volumes-from", other, ALPINE, "true")
    then_refused(world, f"volumes_from 'container:{other}' reaches a container outside the project")


def test_strict_screening_is_refused_for_the_commands_that_do_not_support_it(world):
    when_dockscreen(world, "--strict-screen", "exec", "dockscreen-e2e-none", "true")
    then_status(world, 1)
    then_said(world, "--strict-screen is only supported for audit, create, restart, run, start, buildx bake "
                     "and compose run so far")
    then_nothing_handed_off(world)


def test_an_image_that_runs_as_the_caller_is_refused_and_says_how_to_choose_the_user(world, own_ids_image):
    when_dockscreen(world, "audit", own_ids_image)
    then_refused(world, f"the image's uid {my_ids()[0]} is yours; --allow-me allows it")
    then_said(world, "pass --user UID:GID, --as NAME or --as-me to choose a user")


def test_allow_me_is_refused_for_audit(world, own_ids_image):
    when_dockscreen(world, "--allow-me", "audit", own_ids_image)
    then_status(world, 1)
    then_said(world, "--allow-me is only supported for compose")


def test_an_image_user_from_a_subordinate_range_is_refused(world, subordinate_image):
    when_dockscreen(world, "audit", subordinate_image)
    then_refused(world, "is in a subordinate id range of this host")


def test_choosing_the_user_on_the_command_line_skips_the_image_check(world, own_ids_image):
    when_dockscreen(world, "audit", "--as-me", own_ids_image)
    then_passed(world)
    then_said(world, "the user is set on the command line; the image's own user is not checked")


def test_an_image_user_that_is_a_local_account_is_refused(world):
    require(user_exists(101), "this host has no user 101, which nginx-unprivileged runs as")
    given_image(world, NGINX_UNPRIVILEGED)
    when_dockscreen(world, "audit", NGINX_UNPRIVILEGED)
    then_refused(world, "the image's uid 101 exists on this host (local user ")


def test_an_image_user_outside_the_nobody_range_is_refused_with_mounts(world, stranger_image):
    image, uid = stranger_image
    site = given_outside_dir(world, "site")
    when_dockscreen(world, "audit", image)
    then_passed(world)
    when_dockscreen(world, "audit", "-v", f"{site}:/app/src:ro", image)
    then_refused(world, f"the image's uid {uid} is not in the nobody range 65530-65534",
                 "and there are host mounts")


def test_an_image_section_sets_the_user_of_an_image_pulled_from_its_repository(world):
    given_image(world, NGINX_UNPRIVILEGED)
    site = given_outside_dir(world, "site")
    given_config(world, f"[images.{toml_string('nginxinc/nginx-unprivileged')}]\nuser = \"101:101\"\n")
    when_dockscreen(world, "audit", "-v", f"{site}:/usr/share/nginx/html:ro", NGINX_UNPRIVILEGED)
    then_passed(world)
    then_said(world, "runs as 101:101, the user the config file sets for it")


@pytest.mark.xfail(strict=True, reason=LOCAL_NAME_PROVES_A_PULL)
def test_an_image_section_says_why_it_does_not_apply(world):
    given_image(world, ALPINE)
    world.docker("tag", ALPINE, "dockscreen-e2e/lookalike:1")
    given_config(world, f"[images.{toml_string('dockscreen-e2e/lookalike')}]\nuser = \"65533:65533\"\n")
    when_dockscreen(world, "audit", "dockscreen-e2e/lookalike:1")
    world.docker("image", "rm", "dockscreen-e2e/lookalike:1")
    then_passed(world)
    then_said(world, "note: the config has a section for docker.io/dockscreen-e2e/lookalike, but this "
                     "image was not pulled from there", "instead")


def test_brief_prints_only_the_verdict(world, own_ids_image):
    when_dockscreen(world, "audit", "--brief", own_ids_image)
    then_status(world, 1)
    assert world.result.stdout.count("\n") == 1, world.report()
    assert world.result.last_line.startswith("⊖ denied by audit: the image's uid "), world.report()


def test_an_image_that_is_not_there_fails_the_audit(world):
    when_dockscreen(world, "audit", "--brief", "--pull=never", "dockscreen-e2e/absent:1")
    then_status(world, 3)
    assert world.result.last_line.startswith(f"{FAILED}: docker could not create a container"), world.report()


def test_an_audit_without_an_image_is_a_usage_error(world):
    when_dockscreen(world, "audit")
    then_status(world, 2)
    then_said(world, "usage: dockscreen")


def test_an_audit_whose_command_line_cannot_be_read_is_a_usage_error(world):
    when_dockscreen(world, "audit", "--name")
    then_status(world, 2)
    then_said(world, "--name needs a value", "usage: dockscreen")


def test_an_audit_with_a_user_that_cannot_be_used_is_refused(world):
    when_dockscreen(world, "audit", "--user", "root", ALPINE)
    then_refused(world, "--user takes numeric ids as uid:gid, not 'root'")


def test_an_audit_against_a_daemon_that_may_not_be_this_hosts_is_refused(world):
    when_dockscreen(world, "-H", "tcp://192.0.2.1:2375", "audit", ALPINE)
    then_refused(world, "the daemon is not the default local one")



def test_brief_prints_only_the_verdict_when_it_passes(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "audit", "--brief", ALPINE)
    then_status(world, 0)
    assert world.result.stdout == "✔ audit passed\n", world.report()


def test_an_audit_resolves_as_as_run_does(world):
    name = my_name()
    given_image(world, ALPINE)
    when_dockscreen(world, "audit", "--as", name, ALPINE)
    then_passed(world)
    then_said(world, f"Resolving user {name} to uid ", "the user is set on the command line")


def test_a_named_volume_is_no_finding(world):
    given_image(world, ALPINE)
    when_dockscreen(world, "--strict-screen", "audit", "-v", "dockscreen-e2e-volume:/data", ALPINE, "true")
    world.docker("volume", "rm", "dockscreen-e2e-volume")
    then_passed(world)


def test_an_image_section_may_name_the_repository_with_the_legacy_registry(world):
    given_image(world, NGINX_UNPRIVILEGED)
    given_config(world, "[images.'index.docker.io/nginxinc/nginx-unprivileged']\nuser = \"65533:65533\"\n")
    when_dockscreen(world, "audit", NGINX_UNPRIVILEGED)
    then_passed(world)
    then_said(world, "runs as 65533:65533, the user the config file sets for it")
