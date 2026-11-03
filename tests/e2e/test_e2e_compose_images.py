"""Feature: a service that sets no user runs as a user dockscreen decided from its image, pinned as numbers

Rules (serviceinfo, imageusers, rules.image):
- the images are pulled or built first, as `up` would by the project's pull policy, and each one's user is
  read from the image as docker reads it;
- an image that would run as root runs as the default user instead (65534:65534 unless configured), with
  HOME set to default_home unless the service sets one;
- another image user is checked by the id rules, with the service's mounts, and refused if they refuse it;
- an image section of the config file gives the image a user, but only for an image pulled from that
  repository, never one that is built or tagged locally;
- whatever is decided runs as numeric `uid:gid`, with the image pinned by id and pull_policy: never, in the
  generated file only; a service that this command does not start gets the default user.
"""

import pytest
from realdocker import (
    ALPINE,
    NGINX_UNPRIVILEGED,
    free_id,
    require,
    user_exists,
)
from steps import (
    given_config,
    given_file,
    given_image,
    given_image_section,
    given_service,
    me_user,
    my_ids,
    then_failed,
    then_generated_service,
    then_handed_off,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e

# With docker's containerd image store, RepoDigests lists a digest under every name an image has, so a
# local tag or build passes for having been pulled from that repository (docs/security-review.md).
LOCAL_NAME_PROVES_A_PULL = "a locally tagged or built image counts as pulled from its repository"


def image_id(world, image):
    return world.docker("image", "inspect", "--format", "{{.Id}}", image).stdout.strip()


def test_an_image_that_would_run_as_root_runs_as_the_default_user(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    then_said(world, "service app: running as 65534:65534 instead of root")
    service = then_generated_service(world)
    assert service["user"] == "65534:65534"
    assert service["environment"]["HOME"] == "/tmp"
    assert service["pull_policy"] == "never"
    assert service["image"] == image_id(world, ALPINE)


def test_a_home_the_service_sets_is_kept(world):
    given_image(world, ALPINE)
    given_service(world, "app", environment={"HOME": "/data"})
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world)["environment"]["HOME"] == "/data"


@pytest.mark.parametrize(("setting", "user", "home"), [
    pytest.param("default_user = '65533:65533'", "65533:65533", "/tmp", id="another default user"),
    pytest.param("default_home = ''", "65534:65534", None, id="no default home"),
    pytest.param("default_home = '/home/nobody'", "65534:65534", "/home/nobody", id="another default home"),
])
def test_the_config_file_chooses_the_default_user_and_its_home(world, setting, user, home):
    given_image(world, ALPINE)
    given_config(world, setting)
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    service = then_generated_service(world)
    assert service["user"] == user
    assert (service.get("environment") or {}).get("HOME") == home


def test_a_default_user_of_root_is_warned_about_on_every_run(world):
    given_image(world, ALPINE)
    given_config(world, "default_user = '0:0'")
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    then_said(world, "the configured default user is 0:0: images that would run as root run as root")
    service = then_generated_service(world)
    assert service["user"] == "0:0"
    assert "HOME" not in (service.get("environment") or {})


def test_an_image_that_runs_as_the_caller_needs_allow_me(world, own_ids_image):
    given_service(world, "app", image=own_ids_image)
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: image {own_ids_image}: the image's uid {my_ids()[0]} is yours; pass "
                        "--allow-me to allow it")
    then_nothing_handed_off(world)

    when_dockscreen(world, "--allow-me", "compose", "up")
    then_passed(world)
    service = then_generated_service(world)
    assert service["user"] == me_user()  # as numbers: compose reads nothing from the image's passwd
    assert service["image"] == image_id(world, own_ids_image)


def test_an_image_user_from_a_subordinate_range_is_refused(world, subordinate_image):
    given_service(world, "app", image=subordinate_image)
    when_dockscreen(world, "compose", "up")
    then_refused(world, "is in a subordinate id range of this host (rootless containers)")
    then_nothing_handed_off(world)


def test_an_image_user_that_is_a_local_account_is_refused(world):
    require(user_exists(101), "this host has no user 101, which nginx-unprivileged runs as")
    given_image(world, NGINX_UNPRIVILEGED)
    given_service(world, "web", image=NGINX_UNPRIVILEGED)
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service web: image {NGINX_UNPRIVILEGED}: the image's uid 101 exists on this host")
    then_nothing_handed_off(world)


def test_an_image_user_that_means_nothing_here_needs_the_nobody_range_with_mounts(world, stranger_image):
    image, uid = stranger_image
    given_service(world, "app", image=image)
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world)["user"] == f"{uid}:{uid}"

    given_file(world, "src/index.html")
    given_service(world, "app", image=image, volumes=["./src:/app/src"])
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"the image's uid {uid} is not in the nobody range 65530-65534",
                 "and there are host mounts")
    then_nothing_handed_off(world)


def test_an_image_section_gives_an_image_pulled_from_its_repository_a_user(world):
    given_image(world, NGINX_UNPRIVILEGED)
    given_image_section(world, "nginxinc/nginx-unprivileged", 'user = "65533:65533"')
    given_file(world, "site/index.html")
    given_service(world, "web", image=NGINX_UNPRIVILEGED, volumes=["./site:/usr/share/nginx/html:ro"])
    when_dockscreen(world, "compose", "audit")
    then_passed(world)
    then_said(world, f"service web: no user set; image {NGINX_UNPRIVILEGED} runs as 65533:65533,",
              "the user the config file sets for it")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world, "web")["user"] == "65533:65533"


@pytest.mark.xfail(strict=True, reason=LOCAL_NAME_PROVES_A_PULL)
def test_an_image_section_does_not_apply_to_an_image_tagged_locally(world):
    # alpine, tagged under the name of the repository the section is for: it was not pulled from there
    given_image(world, ALPINE)
    world.docker("tag", ALPINE, "dockscreen-e2e/lookalike:1")
    given_image_section(world, "dockscreen-e2e/lookalike", 'user = "20000:20000"')
    given_service(world, "app", image="dockscreen-e2e/lookalike:1", user="20000:20000",
                  volumes=["./:/project"])
    when_dockscreen(world, "compose", "up")
    world.docker("image", "rm", "dockscreen-e2e/lookalike:1")
    # the name alone passes the checks before the images are there; the check before the run needs proof
    then_refused(world, "service app: user '20000:20000': uid 20000 is not in the nobody range")
    then_nothing_handed_off(world)


@pytest.mark.xfail(strict=True, reason=LOCAL_NAME_PROVES_A_PULL)
def test_an_image_section_does_not_apply_to_an_image_another_service_builds(world):
    given_image(world, ALPINE)
    free = free_id(my_ids())
    require(free is not None, "no id between 20000 and 60000 is free of users, groups and subordinate ranges")
    given_file(world, "Dockerfile", f"FROM {ALPINE}\nUSER {free}:{free}\n")
    given_image_section(world, "dockscreen-e2e/lookalike", f'user = "{free}:{free}"')
    given_service(world, "builder", build={"context": "."}, image="dockscreen-e2e/lookalike:built",
                  user="65534:65534")
    given_service(world, "app", image="dockscreen-e2e/lookalike:built", pull_policy="never",
                  volumes=["./:/project"])
    when_dockscreen(world, "compose", "up")
    world.docker("image", "rm", "dockscreen-e2e/lookalike:built")
    then_refused(world, f"the image's uid {free} is not in the nobody range 65530-65534")
    then_nothing_handed_off(world)


def test_an_image_section_does_not_apply_to_a_built_image(world):
    given_image(world, ALPINE)
    given_file(world, "Dockerfile", f"FROM {ALPINE}\n")
    given_image_section(world, "alpine", 'user = "20000:20000"')
    given_service(world, "app", build={"context": "."}, image=ALPINE)
    when_dockscreen(world, "compose", "audit")
    then_said(world, "note: the config has a section for docker.io/library/alpine,",
              "but the service builds its image")


def test_a_configured_user_applies_to_every_image(world):
    given_image(world, ALPINE)
    given_config(world, 'user = "65533:65533"')
    given_service(world, "app")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world)["user"] == "65533:65533"


def test_a_service_that_is_not_started_gets_the_default_user(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    given_service(world, "debug", profiles=["debug"])
    when_dockscreen(world, "compose", "audit")
    then_said(world, "service debug: no user set and not started by default; dockscreen runs it as the "
                     "default user (65534:65534) if it is started")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    service = then_generated_service(world, "debug")
    assert service["user"] == "65534:65534"
    assert "pull_policy" not in service  # not looked at


def test_a_service_named_on_the_command_line_is_started_and_decided(world):
    given_image(world, ALPINE)
    given_service(world, "app")
    given_service(world, "debug", profiles=["debug"])
    when_dockscreen(world, "compose", "up", "debug")
    then_passed(world)
    assert then_generated_service(world, "debug")["pull_policy"] == "never"


def test_an_image_that_is_not_there_and_not_pulled_fails(world):
    given_service(world, "app", image="dockscreen-e2e/absent:1", pull_policy="never")
    when_dockscreen(world, "compose", "up")
    then_failed(world, "service app: image dockscreen-e2e/absent:1: the image is not available locally",
                status=1)
    then_nothing_handed_off(world)


def test_an_image_that_cannot_be_pulled_fails(world):
    given_service(world, "app", image="dockscreen-e2e/absent:1")
    when_dockscreen(world, "compose", "audit")
    then_failed(world, "docker compose pull app failed")


@pytest.mark.parametrize(("policy", "pulls"), [
    pytest.param("missing", False, id="missing"),
    pytest.param("always", True, id="always"),
    pytest.param("never", False, id="never"),
])
def test_images_are_pulled_by_the_projects_pull_policy(world, policy, pulls):
    given_image(world, ALPINE)
    given_service(world, "app", pull_policy=policy)
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    pulled = [c.argv for c in world.calls if "pull" in c.argv]
    assert bool(pulled) == pulls, world.report()
    assert then_generated_service(world)["pull_policy"] == "never"


def test_a_built_image_is_built_and_pinned_by_name(world):
    given_image(world, ALPINE)
    given_file(world, "Dockerfile", f"FROM {ALPINE}\nUSER 65533:65533\n")
    given_service(world, "app", build={"context": "."})
    when_dockscreen(world, "compose", "up", "--build")
    then_passed(world)
    built = [c.argv for c in world.calls if "build" in c.argv]
    assert built and built[0][-2:] == ["--", "app"], world.report()
    service = then_generated_service(world)
    assert service["user"] == "65533:65533"
    assert "image" not in service or not service["image"].startswith("sha256:")
    world.docker("image", "rm", f"{world.name}-app")


def test_the_images_of_services_with_a_user_are_pulled_but_not_decided(world):
    given_image(world, ALPINE)
    given_service(world, "app", user="65534:65534")
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    service = then_generated_service(world)
    assert service["user"] == "65534:65534" and "pull_policy" not in service
    then_handed_off(world, "up")
