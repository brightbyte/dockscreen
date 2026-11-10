"""Feature: a compose project cannot choose who its containers run as on this host

Rules (Policy.check_user, rules.users, hardening):
- `user:` is `uid:gid`; a name is resolved on this host, never in the image, and a name unknown here is
  refused, as is a uid without a group;
- the project may not choose root, an account or group of this host, a subordinate id, 65535 or
  4294967295, an id above 2147483647, nor the caller's own ids without --allow-me;
- with host mounts only the nobody range, the default user, a configured user and, with --allow-me, the
  caller are allowed;
- the config file widens what is allowed (nobody_range, user, default_user), for every project or one;
- the same goes for the users of hooks.
"""

import pytest
from realdocker import ALPINE, first_subordinate_id, free_id, require, user_exists
from steps import (
    given_config,
    given_env,
    given_file,
    given_image,
    given_project_section,
    given_service,
    me_user,
    my_ids,
    then_generated_service,
    then_nothing_acquired,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(("user", "problem"), [
    pytest.param("0:0", "user '0:0': uid 0 is root", id="root"),
    pytest.param("65534:0", "user '65534:0': gid 0 is root", id="the root group"),
    pytest.param("65535:65534", "user '65535:65534': uid 65535 means \"no id\" to many tools", id="no id"),
    pytest.param("4294967295:65534", "user '4294967295:65534': uid 4294967295 means \"no id\" to many tools",
                 id="no id in 32 bits"),
    pytest.param("4294967296:65534",
                 "user '4294967296:65534': uid 4294967296 is above 2147483647, the largest id docker accepts",
                 id="an id that an older daemon wraps to root"),
    pytest.param("2147483648:65534", "user '2147483648:65534': uid 2147483648 is above 2147483647",
                 id="just above the largest id"),
    pytest.param("20000", "user '20000' has no group, use uid:gid", id="a uid without a group"),
    pytest.param("dockscreen-e2e-nobody",
                 "user 'dockscreen-e2e-nobody' does not exist on this host (names are resolved on this host, "
                 "never in the image)", id="a name unknown here"),
    pytest.param("65534:dockscreen-e2e-nogroup", "group 'dockscreen-e2e-nogroup' does not exist on this host",
                 id="a group name unknown here"),
])
def test_a_user_the_project_may_not_choose_is_refused(world, user, problem):
    given_service(world, "app", user=user)
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: {problem}")
    then_nothing_acquired(world)
    then_nothing_handed_off(world)


def test_a_user_name_is_resolved_on_this_host_and_root_is_refused(world):
    given_service(world, "app", user="root")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "service app: user '0:0': uid 0 is root")
    then_said(world, 'service app: user "root" resolved to "0:0" on this host')


def test_an_account_of_this_host_is_refused(world):
    require(user_exists(1), "this host has no user 1")
    given_service(world, "app", user="1:65534")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "service app: user '1:65534': uid 1 exists on this host (local user ")


def test_a_subordinate_id_is_refused(world):
    first = first_subordinate_id()
    require(first is not None, "/etc/subuid has no range")
    given_service(world, "app", user=f"{first}:65534")
    when_dockscreen(world, "compose", "audit")
    then_refused(world, f"uid {first} is in a subordinate id range of this host (rootless containers)")


def test_the_callers_own_ids_need_allow_me(world):
    given_image(world, ALPINE)
    given_service(world, "app", user=me_user())
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: user '{me_user()}': uid {my_ids()[0]} is yours;",
                 "pass --allow-me to allow it")
    then_nothing_handed_off(world)

    when_dockscreen(world, "--allow-me", "compose", "up")
    then_passed(world)
    assert then_generated_service(world)["user"] == me_user()


def test_a_project_asks_for_the_callers_ids_through_UID_and_GID(world):
    given_image(world, ALPINE)
    given_env(world, UID="0", GID="0")  # what dockscreen passes to compose replaces these
    given_service(world, "app", user="${UID}:${GID}")
    when_dockscreen(world, "--allow-me", "compose", "up")
    then_passed(world)
    call_service = then_generated_service(world)
    assert call_service["user"] == me_user()
    assert (world.handoffs()[0].env["UID"], world.handoffs()[0].env["GID"]) == tuple(map(str, my_ids()))


def test_an_id_that_means_nothing_here_passes_without_host_mounts(world):
    given_image(world, ALPINE)
    free = free_id(my_ids())
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    given_service(world, "app", user=f"{free}:{free}")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world)["user"] == f"{free}:{free}"


def test_with_host_mounts_only_allowed_ids_pass(world):
    free = free_id(my_ids())
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    given_file(world, "data/.keep")
    given_service(world, "app", user=f"{free}:{free}", volumes=["./data:/data"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: user '{free}:{free}': uid {free} is not in the nobody range "
                        "65530-65534, and there are host mounts")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("setting", [
    pytest.param("nobody_range = [20000, 60000]", id="a wider nobody range"),
    pytest.param("user = '{free}:{free}'", id="a configured user"),
    pytest.param("default_user = '{free}:{free}'", id="the default user"),
])
@pytest.mark.parametrize("where", ["top level", "project section"])
def test_the_config_file_allows_ids_with_host_mounts(world, setting, where):
    given_image(world, ALPINE)
    free = free_id(my_ids())
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    text = setting.format(free=free)
    given_config(world, text) if where == "top level" else given_project_section(world, text)
    given_file(world, "data/.keep")
    given_service(world, "app", user=f"{free}:{free}", volumes=["./data:/data"])
    when_dockscreen(world, "compose", "up")
    then_passed(world)


def test_a_project_section_applies_only_to_its_own_directory(world):
    free = free_id(my_ids())
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    given_config(world, f"[projects.'{world.base / 'elsewhere'}']\nnobody_range = [20000, 60000]")
    given_file(world, "data/.keep")
    given_service(world, "app", user=f"{free}:{free}", volumes=["./data:/data"])
    when_dockscreen(world, "compose", "audit")
    then_refused(world, "is not in the nobody range 65530-65534, and there are host mounts")


@pytest.mark.parametrize("hook", ["post_start", "pre_stop"])
def test_a_hook_may_not_run_as_root(world, hook):
    given_service(world, "app", user="65534:65534", **{hook: [{"command": ["true"], "user": "0:0"}]})
    when_dockscreen(world, "compose", "up")
    then_refused(world, "service app: user '0:0': uid 0 is root")
    then_nothing_handed_off(world)


def test_a_hook_user_name_is_resolved_on_this_host(world):
    given_service(world, "app", user="65534:65534", post_start=[{"command": ["true"], "user": "root"}])
    when_dockscreen(world, "compose", "audit")
    then_said(world, 'service app: post_start user "root" resolved to "0:0" on this host')
    then_refused(world, "uid 0 is root")


def test_a_hook_without_a_user_runs_as_the_service(world):
    given_image(world, ALPINE)
    given_service(world, "app", user="65534:65534", post_start=[{"command": ["true"]}])
    when_dockscreen(world, "compose", "up")
    then_passed(world)
