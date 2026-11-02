"""Feature: a compose service gets no privileges and shares nothing of the host's

Rules (policy.SERVICE_CHECKS):
- privileges are refused: privileged, cap_add, devices, device_cgroup_rules, gpus, cgroup_parent,
  external_links, group_add, device reservations, a runtime other than runc, a privileged hook;
- the host's namespaces and other containers' are refused: pid, ipc, uts, userns_mode, cgroup, network_mode;
- cap_drop: [ALL] and no-new-privileges are added where missing, and other security options are refused
  unless the config file allows them;
- a key that is not on the allow list is refused, so a new compose feature is denied until reviewed;
  x- extension fields are ignored;
- a service name that compose would read as an option is refused.

All of these are refused before anything is pulled, built or run.
"""

import pytest
from steps import (
    given_compose,
    given_config,
    given_image,
    given_service,
    then_generated_service,
    then_handed_off,
    then_nothing_acquired,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(("keys", "problem"), [
    pytest.param({"privileged": True}, "privileged is not allowed", id="privileged"),
    pytest.param({"cap_add": ["SYS_ADMIN"]}, "cap_add is not allowed", id="cap_add"),
    pytest.param({"devices": ["/dev/kmsg:/dev/kmsg"]}, "devices is not allowed", id="devices"),
    pytest.param({"device_cgroup_rules": ["c 1:3 mr"]}, "device_cgroup_rules is not allowed",
                 id="device_cgroup_rules"),
    pytest.param({"gpus": "all"}, "gpus is not allowed", id="gpus"),
    pytest.param({"cgroup_parent": "system.slice"}, "cgroup_parent is not allowed", id="cgroup_parent"),
    pytest.param({"external_links": ["db:db"]}, "external_links is not allowed", id="external_links"),
    pytest.param({"group_add": ["65534"]}, "group_add is not allowed", id="group_add of a number"),
    pytest.param({"group_add": ["docker"]}, "group_add is not allowed", id="group_add of a name"),
    pytest.param({"runtime": "runsc"}, "runtime 'runsc' is not allowed", id="runtime"),
    pytest.param({"deploy": {"resources": {"reservations": {"devices": [{"capabilities": ["gpu"]}]}}}},
                 "deploy.resources.reservations.devices grants host devices and is not allowed",
                 id="device reservation"),
    pytest.param({"post_start": [{"command": ["true"], "privileged": True}]},
                 "post_start privileged is not allowed", id="privileged post_start hook"),
    pytest.param({"pre_stop": [{"command": ["true"], "privileged": True}]},
                 "pre_stop privileged is not allowed", id="privileged pre_stop hook"),
])
def test_a_service_that_asks_for_privileges_is_refused(world, keys, problem):
    given_service(world, "app", **keys)
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: {problem}")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


@pytest.mark.parametrize("key", ["pid", "ipc", "uts", "userns_mode", "cgroup", "network_mode"])
def test_a_service_that_shares_a_namespace_of_the_host_is_refused(world, key):
    given_service(world, "app", **{key: "host"})
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: {key}: host shares a namespace outside the project")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("key", ["pid", "ipc", "network_mode"])
def test_a_service_that_joins_another_containers_namespace_is_refused(world, key):
    given_service(world, "app", **{key: "container:someone-else"})
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: {key}: container:someone-else shares a namespace outside the project")
    then_nothing_handed_off(world)


@pytest.mark.parametrize(("option", "problem"), [
    pytest.param("seccomp=unconfined", "security_opt 'seccomp=unconfined' is not allowed", id="seccomp"),
    pytest.param("apparmor=unconfined", "security_opt 'apparmor=unconfined' is not allowed", id="apparmor"),
    pytest.param("label=disable", "security_opt 'label=disable' is not allowed; if bind mounts fail on "
                                  "SELinux, add the :z or :Z mount option instead", id="SELinux label"),
    pytest.param("no-new-privileges:false", "security_opt 'no-new-privileges:false' is not allowed",
                 id="no-new-privileges turned off"),
])
def test_a_security_option_that_weakens_the_container_is_refused(world, option, problem):
    given_service(world, "app", security_opt=[option])
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: {problem}")
    then_nothing_handed_off(world)


def test_the_config_file_can_allow_a_security_option(world):
    given_image(world, "alpine:3.20")
    given_config(world, 'security_opts = ["apparmor=unconfined"]')
    given_service(world, "app", security_opt=["apparmor=unconfined"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    service = then_generated_service(world)
    assert service["security_opt"] == ["apparmor=unconfined", "no-new-privileges:true"]


def test_the_defaults_are_added_to_a_service_that_lacks_them(world):
    given_image(world, "alpine:3.20")
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    then_said(world, 'added cap_drop: ["ALL"] and security_opt: ["no-new-privileges:true"] where missing, '
                     "in services app")
    service = then_generated_service(world)
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]


def test_a_cap_drop_of_the_projects_own_is_extended_with_a_notice(world):
    given_image(world, "alpine:3.20")
    given_service(world, "app", cap_drop=["NET_RAW"], security_opt=["no-new-privileges"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    then_said(world, 'service app: cap_drop lacks ALL; added ["ALL"]')
    service = then_generated_service(world)
    assert service["cap_drop"] == ["NET_RAW", "ALL"]
    assert service["security_opt"] == ["no-new-privileges"]


@pytest.mark.parametrize(("keys", "problem"), [
    pytest.param({"credential_spec": {"file": "spec.json"}}, "key 'credential_spec' is not on the allow list",
                 id="a service key"),
    pytest.param({"deploy": {"placement": {"constraints": ["node.role==manager"]}, "mode": "global",
                             "x-unknown": 1, "rollback_config": {"parallelism": 1}}},
                 None, id="deploy keys on the list"),
    pytest.param({"develop": {"watch": [{"path": "./src", "action": "sync", "target": "/src",
                                         "exec": {"command": "true"}}]}},
                 "develop.watch key 'exec' is not on the allow list", id="a develop.watch key"),
    pytest.param({"post_start": [{"command": ["true"], "x-note": 1}]}, None,
                 id="an extension field in a hook"),
])
def test_keys_off_the_allow_list_are_refused_and_extension_fields_ignored(world, keys, problem):
    given_service(world, "app", keys)
    when_dockscreen(world, "compose", "audit")
    if problem is None:
        then_said(world, "service app")
        assert "is not on the allow list" not in world.output, world.report()
    else:
        then_refused(world, f"service app: {problem}")


def test_a_watch_rule_that_runs_a_command_in_the_container_is_refused(world):
    given_service(world, "app", develop={"watch": [{"path": "./src", "action": "sync+exec", "target": "/src",
                                                     "exec": {"command": "true"}}]})
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "service app: develop.watch action 'sync+exec' is not allowed")


def test_an_extension_field_on_a_service_is_ignored(world):
    given_image(world, "alpine:3.20")
    given_service(world, "app", {"x-team": "web"})
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    then_handed_off(world, "up")


def test_a_service_name_that_compose_would_read_as_an_option_is_refused(world):
    given_service(world, "--ssh")
    when_dockscreen(world, "compose", "up")
    then_refused(world, "service name '--ssh' starts with '-', which compose would read as an option")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


def test_a_service_that_uses_a_model_is_refused(world):
    # models: compose's own key for AI models, which dockscreen has not reviewed. compose does not print the
    # top-level models in its config, so the service's key is what the allow list sees.
    given_service(world, "app", models=["llm"])
    given_compose(world, "models", {"llm": {"model": "ai/smollm2"}})
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "service app: key 'models' is not on the allow list")
    then_nothing_acquired(world)
