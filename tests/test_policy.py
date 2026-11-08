import os

import pytest
from fakes import project_of, rules, texts

from dockscreen.host import config as configuration
from dockscreen.model.container import Container
from dockscreen.model.image import Image, Inspected, Unseen
from dockscreen.model.origin import STRICT, Origin
from dockscreen.model.project import ProjectLocation
from dockscreen.screen import policy
from dockscreen.screen.findings import Finding, Verdict
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.policy import Policy
from dockscreen.screen.rules import project as project_rules
from dockscreen.screen.rules import service as service_rules
from dockscreen.util import messages

# The caller is 4242:4343, and --allow-me is given unless a test says otherwise (see fakes.Accounts
# for the rest of the host).
OWN = "4242:4343"


@pytest.fixture
def project(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "outside").mkdir()
    root = tmp_path / "project"
    root.mkdir()
    (root / "data").mkdir()
    os.symlink(tmp_path / "outside", root / "escape")
    return root


def service(**overrides):
    """A service that satisfies every requirement; tests override one thing at a time."""
    return {"user": OWN, "security_opt": ["no-new-privileges:true"], "cap_drop": ["ALL"], **overrides}


def context(project, extra_dirs=(), allow_me=True):
    return policy.Policy(rules(allow_me=allow_me), tuple(str(d) for d in extra_dirs))


def check(project, config, extra_dirs=(), allow_me=True):
    definition = project_of({"name": "proj", **config}, project)
    return texts(context(project, extra_dirs, allow_me).check_project(definition))


def web(definition=None, project="/p"):
    """The service web, with definition, of a project in project."""
    return project_of({"services": {"web": definition or {}}}, project).service("web")


def problems_for(project, allow_me=True, **overrides):
    return check(project, {"services": {"web": service(**overrides)}}, allow_me=allow_me)


def assert_refused(problems, *reasons):
    """Every reason shows up in some problem, and every problem matches a reason.

    A refusal for an unrelated reason, such as a typo that makes a key unknown, does not pass.
    """
    assert problems, "expected a refusal"
    for problem in problems:
        assert any(reason in problem for reason in reasons), f"unexpected problem: {problem}"
    for reason in reasons:
        assert any(reason in problem for problem in problems), f"missing reason: {reason}"


def test_compliant_config_has_no_problems(project):
    config = {
        "services": {"web": service(
            image="x:1", ports=["80:80"], **{"x-extension": {"anything": 1}},
            volumes=[{"type": "bind", "source": str(project / "data"), "target": "/d",
                      "bind": {"create_host_path": True}},
                     {"type": "volume", "source": "data", "target": "/c"}],
            build={"context": str(project), "dockerfile": "Dockerfile", "args": {"A": "1"}},
            env_file=[{"path": str(project / ".env")}],
            networks={"default": None},
            deploy={"resources": {"limits": {"memory": "1g"}}},
            develop={"watch": [{"path": str(project / "src"), "action": "sync", "target": "/src"}]},
        )},
        "volumes": {"data": {"name": "proj_data", "driver": "local"}},
        "networks": {"default": {"name": "proj_default", "driver": "bridge"}},
        "secrets": {"s": {"file": str(project / "secret.txt")}},
        "x-top": 1,
    }
    assert check(project, config) == []


# --- allowlist ------------------------------------------------------------

def test_unknown_service_key_is_refused_and_extension_keys_are_not(project):
    assert problems_for(project, provider={"type": "x"}) == [
        "service web: key 'provider' is not on the allow list"]
    assert problems_for(project, use_api_socket=True) == [
        "service web: key 'use_api_socket' is not on the allow list"]
    assert problems_for(project, **{"x-anything": 1}) == []


def test_unknown_keys_are_refused_in_nested_structures(project):
    unknown = "'new' is not on the allow list"
    volume_mount = {"type": "volume", "source": "d", "target": "/d", "new": 1}
    assert_refused(problems_for(project, volumes=[volume_mount]), f"mount key {unknown}")
    assert_refused(problems_for(project, volumes=[{"type": "bind", "source": str(project), "target": "/d",
                                                   "bind": {"new": 1}}]),
                   f"mount bind key {unknown}")
    assert_refused(problems_for(project, build={"context": str(project), "new": 1}), f"build key {unknown}")
    assert_refused(problems_for(project, deploy={"new": 1}), f"deploy key {unknown}")
    assert_refused(check(project, {"new_top_level": {}}),
                   "top-level key 'new_top_level' is not on the allow list")
    assert_refused(check(project, {"volumes": {"v": {"name": "proj_v", "new": 1}}}),
                   f"volume v: key {unknown}")
    assert_refused(check(project, {"networks": {"n": {"name": "proj_n", "new": 1}}}),
                   f"network n: key {unknown}")
    assert_refused(check(project, {"secrets": {"s": {"new": 1}}}), f"secrets s: key {unknown}")


def test_every_checked_key_is_outside_the_harmless_list():
    assert not service_rules.HARMLESS_SERVICE_KEYS & service_rules.SERVICE_CHECKS.keys()
    assert service_rules.REQUIRED_SERVICE_KEYS <= service_rules.SERVICE_CHECKS.keys()


# --- users ----------------------------------------------------------------

@pytest.mark.parametrize("user", [
    OWN, "65534:65534", "65530:65531", "4242:65534", "00004242:4343",
    "5000:5000",  # not root, not an account here, and no mounts
])
def test_allowed_users(project, user):
    assert problems_for(project, user=user) == []


@pytest.mark.parametrize("user, reasons", [
    (None, ["user is not set"]),
    ("", ["user is not set"]),
    # names are resolved by hardening; one that is still a name does not exist on this host
    ("app", ["user 'app' does not exist on this host"]),
    ("4242:nogroup", ["group 'nogroup' does not exist on this host"]),
    ("0:0", ["uid 0 is root", "gid 0 is root"]),
    ("4242", ["user '4242' has no group"]),
    ("4242:0", ["gid 0 is root"]),
    ("1000:1000", ["uid 1000 exists on this host (local user daniel)", "gid 1000 exists on this host"]),
    ("999:999", ["gid 999 exists on this host (local group docker)"]),
    ("65535:65535", ['uid 65535 means "no id"', 'gid 65535 means "no id"']),
])
def test_disallowed_users(project, user, reasons):
    assert_refused(problems_for(project, user=user), *reasons)


def test_the_callers_own_ids_need_allow_me(project):
    assert_refused(problems_for(project, allow_me=False, user=OWN),
                   "uid 4242 is yours; pass --allow-me", "gid 4343 is yours; pass --allow-me")


def test_with_host_mounts_only_allowed_ids_pass(project):
    mounts = {"volumes": [{"type": "bind", "source": "./data", "target": "/d"}]}
    assert_refused(problems_for(project, user="5000:5000", **mounts),
                   "uid 5000 is not in the nobody range 65530-65534, and there are host mounts",
                   "gid 5000 is not in the nobody range")
    assert problems_for(project, user="65534:65534", **mounts) == []
    assert problems_for(project, user=OWN, **mounts) == []  # --allow-me: the caller's own ids
    assert problems_for(project, user="5000:5000", secrets=["s"]) != []  # a secret is a mounted host file


def test_subordinate_ids_are_refused(project):
    class SubordinateRanges:
        def contains(self, kind, value):
            return 100000 <= value < 165536

    policy = Policy(rules(subordinate=SubordinateRanges()))
    definition = {"name": "proj", "services": {"web": service(user="100000:5000")}}
    problems = texts(policy.check_project(project_of(definition, project)))
    assert_refused(problems, "uid 100000 is in a subordinate id range")


@pytest.mark.parametrize("value", [["4343"], [65534], ["0"], ["nogroup"]])
def test_group_add_is_refused_whatever_it_names(project, value):
    # Older daemons look a number up as a group name in the image first, so the id cannot be trusted.
    assert_refused(problems_for(project, group_add=value), "group_add is not allowed")
    assert problems_for(project, group_add=[]) == []


# --- privileges -----------------------------------------------------------

@pytest.mark.parametrize("override, reason", [
    ({"privileged": True}, "privileged is not allowed"),
    ({"cap_add": ["SYS_ADMIN"]}, "cap_add is not allowed"),
    ({"devices": ["/dev/sda:/dev/sda"]}, "devices is not allowed"),
    ({"device_cgroup_rules": ["c *:* rwm"]}, "device_cgroup_rules is not allowed"),
    ({"gpus": "all"}, "gpus is not allowed"),
    ({"cgroup_parent": "/"}, "cgroup_parent is not allowed"),
    ({"external_links": ["other:db"]}, "external_links is not allowed"),
    ({"runtime": "nvidia"}, "runtime 'nvidia' is not allowed"),
    ({"pid": "host"}, "pid: host shares a namespace"),
    ({"network_mode": "host"}, "network_mode: host shares a namespace"),
    ({"ipc": "container:other"}, "ipc: container:other shares a namespace"),
    ({"volumes_from": ["container:other"]}, "volumes_from 'container:other' reaches a container"),
])
def test_privilege_escalation_is_refused(project, override, reason):
    assert_refused(problems_for(project, **override), reason)


def test_services_in_the_same_project_may_be_referenced(project):
    assert problems_for(
        project, volumes_from=["other:ro"], network_mode="service:other", runtime="runc") == []


@pytest.mark.parametrize("security_opt, reasons", [
    (["no-new-privileges:true"], []),
    (["no-new-privileges=true"], []),
    (["no-new-privileges"], []),
    (["no-new-privileges:false"],
     ["'no-new-privileges:false' is not allowed", "must include no-new-privileges"]),
    ([], ["must include no-new-privileges"]),
    (None, ["must include no-new-privileges"]),
    (["no-new-privileges:true", "seccomp=unconfined"], ["'seccomp=unconfined' is not allowed"]),
    (["apparmor=unconfined"], ["'apparmor=unconfined' is not allowed", "must include no-new-privileges"]),
    (["no-new-privileges:true", "label=disable"],
     ["'label=disable' is not allowed", "the :z or :Z mount option"]),
    (["no-new-privileges:true", "label:disable"],
     ["'label:disable' is not allowed", "the :z or :Z mount option"]),
])
def test_no_new_privileges_is_required(project, security_opt, reasons):
    config = service()
    config.pop("security_opt")
    if security_opt is not None:
        config["security_opt"] = security_opt
    problems = check(project, {"services": {"web": config}})
    if reasons:
        assert_refused(problems, *reasons)
    else:
        assert problems == []


@pytest.mark.parametrize("cap_drop, ok", [(["ALL"], True), (["all"], True), (["ALL", "NET_RAW"], True),
                                          (["NET_RAW"], False), ([], False), (None, False)])
def test_cap_drop_all_is_required(project, cap_drop, ok):
    config = service()
    config.pop("cap_drop")
    if cap_drop is not None:
        config["cap_drop"] = cap_drop
    problems = check(project, {"services": {"web": config}})
    if ok:
        assert problems == []
    else:
        assert_refused(problems, "cap_drop must include ALL")


# --- mounts ---------------------------------------------------------------

def bind(source):
    return {"type": "bind", "source": str(source), "target": "/x"}


@pytest.mark.parametrize("selinux", ["z", "Z"])
def test_selinux_relabel_option_on_a_bind_mount_is_allowed(project, selinux):
    # Compose normalises `./data:/data:z` to bind.selinux; it replaces label=disable.
    mount = {**bind(project), "bind": {"selinux": selinux}}
    assert problems_for(project, volumes=[mount]) == []


def test_selinux_relabel_does_not_allow_a_bind_mount_outside_the_project(project):
    mount = {**bind("/etc"), "bind": {"selinux": "Z"}}
    assert_refused(problems_for(project, volumes=[mount]), "bind mount '/etc' is outside")


def test_the_configured_user_is_allowed_for_the_service_with_mounts(project):
    policy = Policy(rules())
    mounted = web({"volumes": [bind(project / "data")]}, project)
    assert policy.check_user("900:900", mounted)  # refused: not in the nobody range, with mounts
    configured = Policy(rules(), configured_user=(900, 900))
    assert configured.check_user("900:900", mounted) == []
    assert configured.check_user("900:65534", mounted) == []  # each id on its own, as for nobody
    assert configured.check_user("901:900", mounted) == [
        "user '901:900': uid 901 is not in the nobody range 65530-65534, and there are host mounts"]


def test_security_opts_from_the_config_file_are_allowed_too(project):
    policy = Policy(rules(), security_opts=("seccomp=/etc/strict.json",))
    assert policy.check_security_opt(["no-new-privileges:true", "seccomp=/etc/strict.json"], web()) == []
    assert policy.check_security_opt(["seccomp=/etc/strict.json"], web()) == [
        "security_opt must include no-new-privileges:true"]  # still required


def test_a_mount_outside_says_how_the_config_file_can_allow_it(project):
    config_file = "/home/me/.config/dockscreen/config.toml"
    policy = Policy(rules(allow_me=True), config_file=config_file)
    assert policy._check_mounts([bind("/srv/data")], web(project=project)) == [
        (f"bind mount '/srv/data' is outside {project}; to allow it, add a directory that contains it to "
         f'mount_dirs under [projects."{project}"] in /home/me/.config/dockscreen/config.toml')]


def test_bind_mount_outside_project_is_refused(project):
    assert_refused(problems_for(project, volumes=[bind("/var/run/docker.sock")]),
                   "bind mount '/var/run/docker.sock' is outside")


def test_bind_mount_through_symlink_out_of_project_is_refused(project):
    # The path looks inside the project but its realpath is not.
    assert_refused(problems_for(project, volumes=[bind(project / "escape")]), "/escape' is outside")


def test_bind_mount_of_sibling_with_common_prefix_is_refused(project):
    assert_refused(problems_for(project, volumes=[bind(str(project) + "-other")]), "-other' is outside")


def test_mounts_from_extra_dirs_are_allowed(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[
        bind(outside), bind(outside / "deeper"), bind(project / "escape"),  # last: symlink into outside
    ])}}

    assert check(project, config, [outside]) == []
    assert len(check(project, config)) == 3


def test_extra_dirs_do_not_allow_their_siblings_or_other_mounts(project):
    outside = project.parent / "outside"
    config = {"services": {"web": service(volumes=[bind(project.parent / "outside-other"), bind("/etc")])}}
    assert len(check(project, config, [outside])) == 2


# --- build ----------------------------------------------------------------

def test_build_context_outside_project_is_refused(project):
    assert problems_for(project, build={"context": "/"}) == [
        f"service web: build context '/' is outside {project}"]


@pytest.mark.parametrize("build, reason", [
    ({"dockerfile": "../../etc/Dockerfile"}, "build dockerfile '../../etc/Dockerfile' is outside"),
    ({"additional_contexts": {"lib": "/usr/lib"}}, "build additional_contexts 'lib': '/usr/lib' is outside"),
    ({"network": "host"}, "build network 'host' is not allowed"),
    ({"privileged": True}, "build privileged is not allowed"),
    ({"ssh": ["default"]}, "build ssh forwards your SSH agent"),
    ({"cache_to": ["type=local,dest=/tmp/x"]}, "build key 'cache_to' is not on the allow list"),
    ({"entitlements": ["network.host"]}, "build key 'entitlements' is not on the allow list"),
    ({"x-bake": {"output": ["type=local,dest=/home/me"]}}, "build key 'x-bake' is not on the allow list"),
])
def test_unsafe_build_options_are_refused_when_building_and_running(project, build, reason):
    build = {"context": str(project), **build}
    definition = project_of({"name": "proj", "services": {"web": {"build": build}}}, project)
    build_only = texts(context(project).check_project_build(definition))

    assert_refused(problems_for(project, build=build), reason)
    assert_refused(build_only, reason)


def test_remote_build_contexts_and_images_are_not_paths(project):
    assert problems_for(project, build={
        "context": "https://example.org/repo.git",
        "additional_contexts": {"base": "docker-image://alpine", "other": "service:db"},
    }) == []


def test_build_config_check_ignores_runtime_policy(project):
    config = {"name": "proj", "services": {"web": {"build": {"context": str(project)}, "privileged": True,
                                                   "user": "0"}}}
    assert context(project).check_project_build(project_of(config, project)) == []


def test_build_config_check_covers_secret_files(project):
    config = {"name": "proj", "secrets": {"s": {"file": "/etc/shadow"}}}
    assert_refused(texts(context(project).check_project_build(project_of(config, project))),
                   "file '/etc/shadow' is outside")


# --- named volumes, networks, secrets -------------------------------------

def test_external_and_foreign_named_volumes_and_networks_are_refused(project):
    external = "external resources are not allowed"
    assert_refused(check(project, {"volumes": {"v": {"name": "v", "external": True}}}), external)
    assert_refused(check(project, {"volumes": {"v": {"name": "other_v"}}}),
                   "name 'other_v' is not the project-scoped 'proj_v'")
    assert_refused(check(project, {"networks": {"n": {"name": "n", "external": True}}}), external)
    assert_refused(check(project, {"networks": {"n": {"name": "other_n"}}}),
                   "name 'other_n' is not the project-scoped 'proj_n'")
    unnamed = check(project, {"volumes": {"v": {"name": "proj_v"}}, "networks": {"n": {}}} | {"name": ""})
    assert unnamed.count("config has no project name") == 1  # once, not for each volume and network


def test_volume_drivers_and_options(project):
    def volume(**fields):
        return check(project, {"volumes": {"v": {"name": "proj_v", **fields}}})

    assert volume(driver="local", driver_opts={"type": "tmpfs", "device": "tmpfs"}) == []
    assert volume(driver_opts={"type": "none", "o": "bind", "device": str(project / "data")}) == []
    assert_refused(volume(driver="rclone"), "driver 'rclone' is not allowed")
    assert_refused(volume(driver_opts={"type": "nfs", "device": ":/export"}),
                   "driver_opts type 'nfs' is not allowed")
    assert_refused(volume(driver_opts={"type": "none", "o": "bind", "device": "relative/dir"}),
                   "device 'relative/dir' must be an absolute path")
    assert_refused(volume(driver_opts={"type": "none", "o": "bind", "device": "/etc"}),
                   "device '/etc' is outside")


@pytest.mark.parametrize("opts", [
    {"type": "tmpfs", "device": "/etc", "o": "bind"},
    {"type": "tmpfs", "device": "/etc", "o": "rbind"},
    {"type": "tmpfs", "device": "tmpfs", "o": "size=1m, Bind"},
    {"type": "tmpfs", "device": "/etc"},
])
def test_a_tmpfs_volume_cannot_be_made_a_bind_mount_of_a_host_path(project, opts):
    # The kernel ignores the filesystem type when the bind flag is set.
    problems = check(project, {"volumes": {"v": {"name": "proj_v", "driver_opts": opts}}})
    assert_refused(problems, "a tmpfs volume must not name a device or bind")


def test_volume_driver_opts_are_an_allowlist_and_bind_needs_a_device(project):
    def volume(opts):
        return check(project, {"volumes": {"v": {"name": "proj_v", "driver_opts": opts}}})

    assert volume({"type": "tmpfs", "device": "tmpfs", "o": "size=1m,uid=1000"}) == []
    assert_refused(volume({"type": "tmpfs", "size": "1m"}), "driver_opts key 'size' is not on the allow list")
    assert_refused(volume({"type": "none", "o": "bind"}), "bind needs a device")


def test_the_id_rules_for_host_mounts_apply_to_a_service_of_a_bind_volume(project):
    def check_user(volumes):
        web = service(user="5000:5001", volumes=[{"type": "volume", "source": "d", "target": "/h"}])
        return check(project, {"services": {"web": web}, "volumes": volumes})

    named = {"d": {"name": "proj_d"}}
    bound = {"d": {"name": "proj_d", "driver_opts": {"type": "none", "o": "bind",
                                                      "device": str(project / "data")}}}
    assert check_user(named) == []  # nothing on the host is owned by 5000
    assert check_user(bound)  # with the project's files in reach, it is refused like any bind mount


def test_extra_dirs_apply_to_volume_devices_but_not_to_build_contexts(project):
    outside = str(project.parent / "outside")
    config = {
        "volumes": {"v": {"name": "proj_v", "driver_opts": {"o": "bind", "device": outside}}},
        "services": {"web": service(build={"context": outside})},
    }
    assert check(project, config, [outside]) == [
        f"service web: build context {outside!r} is outside {project}"]


def test_network_drivers_and_options(project):
    def network(**fields):
        return check(project, {"networks": {"n": {"name": "proj_n", **fields}}})

    assert network(driver="bridge", ipam={"config": [{"subnet": "10.0.0.0/24"}]},
                   driver_opts={"com.docker.network.driver.mtu": "1400"}) == []
    assert_refused(network(driver="host"), "driver 'host' is not allowed")
    assert_refused(network(driver="macvlan"), "driver 'macvlan' is not allowed")
    assert_refused(network(ipam={"driver": "custom"}), "ipam driver 'custom' is not allowed")
    assert_refused(network(driver_opts={"com.docker.network.bridge.name": "docker0"}),
                   "driver_opts key 'com.docker.network.bridge.name' is not on the allow list")


def test_secrets_and_configs(project):
    assert_refused(check(project, {"secrets": {"s": {"file": "/etc/shadow"}}}),
                   "file '/etc/shadow' is outside")
    assert_refused(check(project, {"secrets": {"s": {"environment": "AWS_SECRET_ACCESS_KEY"}}}),
                   "environment 'AWS_SECRET_ACCESS_KEY' copies a variable")
    assert_refused(check(project, {"configs": {"c": {"external": True}}}),
                   "external resources are not allowed")
    assert check(project, {"configs": {"c": {"content": "inline"}}}) == []


# --- host files and structured keys ---------------------------------------

@pytest.mark.parametrize("key", ["env_file", "label_file"])
@pytest.mark.parametrize("value, path", [
    ("../x.env", "../x.env"),  # relative paths resolve against the project
    (["/etc/environment"], "/etc/environment"),
    ([{"path": "/home/me/.aws/env"}], "/home/me/.aws/env"),
])
def test_env_and_label_files_outside_project_are_refused(project, key, value, path):
    assert_refused(problems_for(project, **{key: value}), f"{key} {path!r} is outside")


def test_develop_watch(project):
    def watch(**rule):
        return problems_for(project, develop={"watch": [{"path": str(project), "action": "sync", **rule}]})

    assert watch() == []
    assert_refused(watch(action="sync+exec"), "develop.watch action 'sync+exec' is not allowed")
    assert_refused(watch(exec={"command": "x"}), "develop.watch key 'exec' is not on the allow list")
    assert_refused(watch(path="/etc"), "develop.watch path '/etc' is outside")


def test_deploy_cannot_reserve_devices(project):
    devices = {"resources": {"reservations": {"devices": [{"driver": "nvidia"}]}}}
    assert_refused(problems_for(project, deploy=devices),
                   "deploy.resources.reservations.devices grants host devices")
    assert problems_for(project, deploy={"resources": {"reservations": {"memory": "1g"}}}) == []


def test_lifecycle_hooks_cannot_escalate(project):
    assert_refused(problems_for(project, post_start=[{"command": "x", "privileged": True}]),
                   "post_start privileged is not allowed")
    assert_refused(problems_for(project, pre_stop=[{"command": "x", "user": "0:0"}]),
                   "uid 0 is root", "gid 0 is root")
    assert problems_for(project, post_start=[{"command": "x", "user": OWN}]) == []


# --- fix ------------------------------------------------------------------

def test_a_service_name_that_compose_would_read_as_an_option_is_refused(project):
    config = {"services": {"--ssh": service(), "web": service()}}
    reason = "service name '--ssh' starts with '-', which compose would read as an option"

    assert check(project, config) == [reason]
    assert texts(context(project).check_project_build(project_of({"name": "proj", **config}, project))) == [
        reason]


# --- containers ---------------------------------------------------------------

def check_container(user="", user_origin=Origin.IMAGE, trust=None, **host):
    info = {"Config": {"User": user},
            "HostConfig": {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"], **host}}
    policy = Policy(rules()).with_trust(trust) if trust else Policy(rules())
    return policy.check_container(Container(info, "/work", user_origin))


def test_a_hardened_container_with_nothing_else_has_no_findings():
    assert check_container(NetworkMode="default", IpcMode="private", Runtime="runc") == []


def test_a_containers_bind_mounts_are_judged_against_the_current_directory_once_each():
    found = check_container(Binds=["/etc:/etc:ro", "/work/src:/src"],
                            Mounts=[{"Type": "bind", "Source": "/etc", "Target": "/etc"}])

    assert texts(found) == ["bind mount '/etc' is outside /work"]


def test_a_containers_volumes_from_and_devices_are_found():
    found = check_container(VolumesFrom=["db"], Devices=[{"PathOnHost": "/dev/kvm"}])
    assert texts(found) == [
        "devices is not allowed", "volumes_from 'container:db' reaches a container outside the project"]


def test_a_containers_user_is_judged_only_when_the_command_line_chose_it():
    assert check_container(user="0:0") == []  # the image's: run decides that one, not this
    assert texts(check_container(user="0:0", user_origin=Origin.COMMAND_LINE)) == [
        "user '0:0': uid 0 is root", "user '0:0': gid 0 is root"]


def test_what_a_containers_command_line_asks_for_is_refused_only_where_it_is_not_trusted():
    found = check_container(user="0:0", user_origin=Origin.COMMAND_LINE, Privileged=True)
    strict = check_container(user="0:0", user_origin=Origin.COMMAND_LINE, trust=STRICT, Privileged=True)

    assert {(type(f), f.severity) for f in found} == {(Notice, NoticeSeverity.WARNING)}
    assert {(type(f), f.verdict) for f in strict} == {(Finding, Verdict.REFUSED)}


def test_each_key_is_judged_as_where_its_value_comes_from():
    service = {"user": "0:0", "cap_drop": [], "security_opt": ["no-new-privileges:true"]}
    origins = {"user": Origin.CONFIG, "cap_drop": Origin.DOCKSCREEN}

    web = project_of({"services": {"web": service}}, origins={"web": origins}).service("web")

    found = policy.Policy(rules()).check_service(web)

    # the config file is trusted, dockscreen is not: its values are checked once more
    assert [(str(f), type(f)) for f in found] == [
        ("user '0:0': uid 0 is root", Notice), ("user '0:0': gid 0 is root", Notice),
        ("cap_drop must include ALL", Finding)]


# --- the daemon, the project name, and the command line's users ----------------

def test_a_daemon_that_may_not_be_this_hosts_is_refused():
    assert policy.Policy(rules()).check_daemon(False) == []
    assert texts(policy.Policy(rules()).check_daemon(True)) == [project_rules.REMOTE_MESSAGE]


def test_a_project_directory_is_refused_for_each_reason_it_cannot_be_trusted():
    assert policy.Policy(rules()).check_location(ProjectLocation("/p")) == []

    location = ProjectLocation("/home/me", foreign=True, redirects=("/home/me/.env",),
                               sensitive=("/home/me",))
    found = policy.Policy(rules()).check_location(location)

    assert [f.verdict for f in found] == [Verdict.REFUSED] * 3
    first, second, third = texts(found)
    assert first.startswith("the nearest compose file is in /home/me, which is your home directory")
    assert second.startswith("/home/me/.env sets COMPOSE_FILE")
    assert third.startswith("the project directory /home/me contains /home/me;")


def test_a_mount_dir_that_contains_a_sensitive_path_is_pointed_out():
    [warning] = policy.Policy(rules()).check_mount_dirs({"/srv": [], "/home": ["/home/me", "/home/me/.x"]})

    assert str(warning) == "the configured mount dir /home contains /home/me, so containers can mount it"
    assert warning.severity is NoticeSeverity.WARNING and warning.mark is messages.WARN


def test_what_services_take_from_the_shell_is_pointed_out_by_name_per_service():
    found = policy.Policy(rules()).check_shell_env({"db": ["HOME"], "web": ["A", "TOKEN"], "job": []})

    assert [(f.subject, f.severity) for f in found] == [("service db", NoticeSeverity.WARNING)] + [
        ("service web", NoticeSeverity.WARNING)]
    assert found[1].shown == "service web: environment variables taken from your shell: A, TOKEN"


@pytest.mark.parametrize("spec", ["1000:1000", "0:0", "65534:65534", "1000:0"])
def test_user_option_takes_numeric_ids(spec):
    assert policy.Policy(rules()).check_user_option(spec) == []


@pytest.mark.parametrize("spec", [
    "alice", "nobody", "root", "1000:staff", "alice:1000", "", "1000:", ":1000", "-1", "1000", "0",
])
def test_user_option_refuses_everything_else_and_points_at_the_alternatives(spec):
    [refusal] = texts(policy.Policy(rules()).check_user_option(spec))
    assert "--user takes numeric ids as uid:gid" in refusal
    assert "--as NAME runs as a local user, --as-me as yourself" in refusal


def test_a_user_option_with_a_uid_alone_says_to_give_the_group():
    [refusal] = texts(policy.Policy(rules()).check_user_option("1000"))
    assert "not '1000'; give the group too, as uid:gid" in refusal


def test_as_option_needs_the_name_of_an_account_on_this_host():
    assert policy.Policy(rules()).check_as_option("alice", (4242, 4343)) == []
    assert texts(policy.Policy(rules()).check_as_option("ghost", None)) == [
        "user 'ghost' does not exist on this host; use --user with a numeric id"]
    for name in ("1000", "alice:staff", ""):
        [refusal] = texts(policy.Policy(rules()).check_as_option(name, (1, 1)))
        assert "--as takes the name of a local user" in refusal


# --- images ---------------------------------------------------------------------

PASSWD = "root:x:0:0::/root:/bin/sh\napp:x:100000:100001::/home/app:/bin/sh\n"


def inspected(user, mounts=False):
    """An image whose own user is user, looked at through a container created with it, files read."""
    return Inspected(Image("app:1", "sha256:1"), user, user, mounts).with_user_files(PASSWD, "")


@pytest.mark.parametrize("user, origin, root, runs_as", [
    ("root", Origin.DOCKSCREEN, True, (65534, 65534)),  # dockscreen's default user instead
    ("app", Origin.IMAGE, False, (100000, 100001)),
])
def test_an_images_own_user_is_judged_from_its_files_without_docker(user, origin, root, runs_as):
    found = policy.Policy(rules()).check_image(inspected(user), Origin.IMAGE)

    assert (found.origin, found.replaces_root, found.user, found.refused) == (origin, root, runs_as, False)


def test_the_default_user_the_config_file_sets_comes_from_it():
    settings = configuration.Config(default_user=(9, 9), configured=frozenset({"default_user"}))
    found = policy.Policy.for_settings(settings, rules()).check_image(inspected("root"), Origin.IMAGE)
    assert (found.origin, found.replaces_root, found.user) == (Origin.CONFIG, True, (9, 9))


def test_an_image_user_the_id_rules_refuse_with_host_mounts_is_refused():
    found = policy.Policy(rules()).check_image(inspected("app", mounts=True), Origin.IMAGE)
    assert found.refused and str(found.findings[0]).startswith("the image's uid 100000")


def test_the_files_are_needed_only_for_the_images_own_user_when_none_is_configured():
    plain, configured = policy.Policy(rules()), policy.Policy(rules(), configured_user=(7, 7))

    assert plain.needs_user_files(Origin.IMAGE)
    assert not plain.needs_user_files(Origin.COMMAND_LINE)
    assert not configured.needs_user_files(Origin.IMAGE)
    found = configured.check_image(inspected("root")._replace(passwd=None), Origin.IMAGE)
    assert (found.origin, found.replaces_root, found.user) == (Origin.CONFIG, False, (7, 7))


def test_a_projects_images_are_judged_as_they_were_looked_at(project):
    looked_at = {"web": inspected("app", mounts=True), "db": Unseen(Image("db:1"), "not here")}

    found = context(project).check_images(looked_at)

    assert [(f.subject, f.verdict) for f in found] == [("service web", Verdict.REFUSED),
                                                    ("service db", Verdict.FAILED)]
    assert str(found[1]) == "service db: image db:1: not here"


def test_paths_are_judged_against_the_targets_directory_not_the_policys(tmp_path):
    (tmp_path / "a").mkdir()
    one_policy = policy.Policy(rules())
    build = {"services": {"web": {"build": {"context": str(tmp_path / "a")}}}}

    assert one_policy.check_project_build(project_of(build, tmp_path / "a")) == []
    [outside] = one_policy.check_project_build(project_of(build, tmp_path / "b"))
    assert str(outside).endswith(f"is outside {tmp_path / 'b'}")
