"""Feature: a compose project reaches no host files outside its directory

Rules (policy):
- a bind mount's source, with symlinks resolved, is inside the project directory or a mount_dirs entry
  of the config file (the top level's or the project section's);
- a named volume is the project's own: not external, named as compose names it, of the local driver, and
  its driver_opts do not make it a bind mount of a host path or a network mount;
- networks are the project's own, of the bridge or none driver;
- files read from the host (env_file, secrets, configs, develop.watch paths) are inside the project;
  a secret may not copy a variable from dockscreen's environment;
- volumes_from may name the project's services, not other containers.

All of these are refused before anything is pulled, built or run.
"""

import pytest
from realdocker import ALPINE
from steps import (
    given_compose,
    given_config,
    given_file,
    given_image,
    given_outside_dir,
    given_project_section,
    given_service,
    given_symlink,
    then_generated_service,
    then_nothing_acquired,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize("source", [
    pytest.param("/etc", id="a system directory"),
    pytest.param("/", id="the root"),
    pytest.param("/var/run/docker.sock", id="the docker socket"),
    pytest.param("/proc/1/root", id="the host root through procfs"),
    pytest.param("/etc/..", id="the root, spelled otherwise"),
])
def test_a_bind_mount_from_outside_the_project_is_refused(world, source):
    given_service(world, "app", volumes=[{"type": "bind", "source": source, "target": "/mnt"}])
    when_dockscreen(world, "compose", "up")
    then_refused(world, "service app: bind mount '")
    then_said(world, f"' is outside {world.project_dir}")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


def test_a_bind_mount_from_the_home_directory_is_refused(world):
    given_service(world, "app", volumes=["~/.ssh:/ssh:ro"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, "/.ssh' is outside")
    then_nothing_handed_off(world)


def test_a_bind_mount_inside_the_project_passes(world):
    given_image(world, ALPINE)
    given_file(world, "data/index.html", "hello")
    given_service(world, "app", volumes=["./data:/data:ro"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    service = then_generated_service(world)
    assert service["volumes"][0]["source"] == str(world.project_dir / "data")


def test_a_symlink_in_the_project_is_followed_out_of_it(world):
    given_symlink(world, "data", "/etc")
    given_service(world, "app", volumes=["./data:/data:ro"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: bind mount '{world.project_dir / 'data'}' is outside")
    then_nothing_handed_off(world)


def test_a_dangling_symlink_is_judged_by_where_it_points(world):
    given_symlink(world, "data", "/etc/dockscreen-e2e-does-not-exist")
    given_service(world, "app", volumes=[{"type": "bind", "source": "./data", "target": "/data",
                                          "bind": {"create_host_path": False}}])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"service app: bind mount '{world.project_dir / 'data'}' is outside")


@pytest.mark.parametrize("where", ["top level", "project section"])
def test_mount_dirs_of_the_config_file_allow_a_bind_mount_outside_the_project(world, where):
    given_image(world, ALPINE)
    site = given_outside_dir(world, "site")
    setting = f"mount_dirs = ['{site}']"
    given_config(world, setting) if where == "top level" else given_project_section(world, setting)
    given_service(world, "app", volumes=[f"{site}:/site:ro"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)


def test_the_refusal_says_how_the_config_file_can_allow_the_mount(world):
    site = given_outside_dir(world, "site")
    given_service(world, "app", volumes=[f"{site}:/site:ro"])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"service app: bind mount '{site}' is outside {world.project_dir}; to allow it, add "
                        "a directory that contains it to mount_dirs under "
                        f'[projects."{world.project_dir}"] '
                        f"in {world.config_file}")


def test_a_mount_dir_that_contains_a_sensitive_path_is_warned_about(world):
    given_image(world, ALPINE)
    given_config(world, "mount_dirs = ['/var']")
    given_service(world, "app")
    when_dockscreen(world, "compose", "audit")
    then_passed(world)
    then_said(world, "the configured mount dir /var contains /var, so containers can mount it")


@pytest.mark.parametrize(("mount", "problem"), [
    pytest.param({"type": "npipe", "source": "//./pipe/docker_engine", "target": "/pipe"},
                 "mount type 'npipe' is not allowed", id="a named pipe"),
    pytest.param({"type": "cluster", "source": "vol", "target": "/c"},
                 "mount type 'cluster' is not allowed", id="a cluster volume"),
])
def test_a_mount_of_a_type_that_is_not_allowed_is_refused(world, mount, problem):
    given_service(world, "app", volumes=[mount])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"service app: {problem}")


@pytest.mark.parametrize(("volume", "problem"), [
    pytest.param({"external": True}, "external resources are not allowed, they may belong to another project",
                 id="external"),
    pytest.param({"name": "someone-elses-data"}, "name 'someone-elses-data' is not the project-scoped",
                 id="the name of another volume"),
    pytest.param({"driver": "nfs"}, "driver 'nfs' is not allowed", id="another driver"),
    pytest.param({"driver_opts": {"type": "none", "o": "bind", "device": "/etc"}}, "device '/etc' is outside",
                 id="a bind mount of /etc"),
    pytest.param({"driver_opts": {"type": "none", "o": "bind", "device": "data"}},
                 "device 'data' must be an absolute path", id="a relative device"),
    pytest.param({"driver_opts": {"type": "nfs", "o": "addr=10.0.0.1", "device": ":/export"}},
                 "driver_opts type 'nfs' is not allowed", id="a network mount"),
    pytest.param({"driver_opts": {"type": "tmpfs", "o": "bind", "device": "/etc"}},
                 "a tmpfs volume must not name a device or bind", id="a tmpfs with the bind flag"),
    pytest.param({"driver_opts": {"type": "tmpfs", "o": "size=1m, Bind"}},
                 "a tmpfs volume must not name a device or bind", id="bind spelled otherwise"),
    pytest.param({"driver_opts": {"o": "rbind"}}, "bind needs a device", id="bind without a device"),
    pytest.param({"driver_opts": {"type": "tmpfs", "size": "1m"}},
                 "driver_opts key 'size' is not on the allow list", id="another driver option"),
])
def test_a_named_volume_that_is_not_the_projects_own_is_refused(world, volume, problem):
    given_compose(world, "volumes", {"data": volume})
    given_service(world, "app", volumes=["data:/data"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"volume data: {problem}")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


def test_a_named_volume_bound_to_the_project_is_a_host_mount_for_the_id_rules(world):
    given_file(world, "data/.keep")
    given_compose(world, "volumes", {"data": {"driver_opts": {"type": "none", "o": "bind",
                                                              "device": str(world.project_dir / "data")}}})
    given_service(world, "app", user="20000:20000", volumes=["data:/data"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, "service app: user '20000:20000': uid 20000 is not in the nobody range "
                        "65530-65534, and there are host mounts")
    then_nothing_handed_off(world)


def test_a_plain_tmpfs_volume_passes(world):
    given_image(world, ALPINE)
    given_compose(world, "volumes", {"scratch": {"driver_opts": {"type": "tmpfs", "device": "tmpfs",
                                                                 "o": "size=1m"}}})
    given_service(world, "app", volumes=["scratch:/scratch"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)


@pytest.mark.parametrize(("network", "problem"), [
    pytest.param({"external": True}, "external resources are not allowed", id="external"),
    pytest.param({"name": "bridge"}, "name 'bridge' is not the project-scoped",
                 id="the name of another network"),
    pytest.param({"driver": "macvlan"}, "driver 'macvlan' is not allowed", id="another driver"),
    pytest.param({"driver_opts": {"com.docker.network.bridge.name": "docker0"}},
                 "driver_opts key 'com.docker.network.bridge.name' is not on the allow list",
                 id="a driver option"),
    pytest.param({"ipam": {"driver": "dhcp"}}, "ipam driver 'dhcp' is not allowed", id="an ipam driver"),
])
def test_a_network_that_is_not_the_projects_own_is_refused(world, network, problem):
    given_compose(world, "networks", {"net": network})
    given_service(world, "app", networks=["net"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"network net: {problem}")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("kind", ["secrets", "configs"])
def test_a_secret_or_config_from_outside_the_project_is_refused(world, kind):
    given_compose(world, kind, {"key": {"file": "/etc/hostname"}})
    given_service(world, "app", **{kind: ["key"]})
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"{kind} key: file '/etc/hostname' is outside {world.project_dir}")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


@pytest.mark.parametrize(("secret", "problem"), [
    pytest.param({"environment": "HOME"},
                 "environment 'HOME' copies a variable from dockscreen's environment",
                 id="a variable"),
    pytest.param({"external": True}, "external resources are not allowed", id="external"),
])
def test_a_secret_that_is_not_a_file_of_the_project_is_refused(world, secret, problem):
    given_compose(world, "secrets", {"key": secret})
    given_service(world, "app", secrets=["key"])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"secrets key: {problem}")


def test_a_secret_of_the_project_passes_and_counts_as_a_host_mount(world):
    given_image(world, ALPINE)
    given_file(world, "token.txt", "not-a-secret")
    given_compose(world, "secrets", {"token": {"file": "./token.txt"}})
    given_service(world, "app", user="20000:20000", secrets=["token"])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "uid 20000 is not in the nobody range 65530-65534, and there are host mounts")


@pytest.mark.parametrize("key", ["env_file", "label_file"])
def test_a_file_read_on_the_host_from_outside_the_project_is_refused(world, key):
    outside = given_outside_dir(world) / "values"
    outside.write_text("A=1\n")
    given_service(world, "app", **{key: [str(outside)]})
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"service app: {key} '{outside}' is outside {world.project_dir}")


def test_a_watch_path_outside_the_project_is_refused(world):
    outside = given_outside_dir(world)
    rule = {"path": str(outside), "action": "sync", "target": "/src"}
    given_service(world, "app", develop={"watch": [rule]})
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"service app: develop.watch path '{outside}' is outside {world.project_dir}")


def test_volumes_of_another_container_are_refused(world):
    given_service(world, "app", volumes_from=["container:someone-else"])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "service app: volumes_from 'container:someone-else'",
                 "reaches a container outside the project")


def test_volumes_of_another_service_of_the_project_pass(world):
    given_image(world, ALPINE)
    given_compose(world, "volumes", {"data": {}})
    given_service(world, "db", volumes=["data:/data"])
    given_service(world, "app", volumes_from=["db"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    service = then_generated_service(world, "app")
    assert service["volumes_from"] == ["db"]
