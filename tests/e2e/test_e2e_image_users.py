"""Feature: the user an image runs as is read from the image's own files, as docker reads them

Rules (imageuser, rules.image, Scope.look, dockerclient.read_file):
- the image's USER is resolved in its own /etc/passwd and /etc/group, read out of a container that never
  starts; a missing file has no names in it;
- a name the image does not define is refused, as docker would refuse to start it;
- a number that cannot be read in passwd counts as 0, as docker reads it, so the image runs as the default
  user instead of root;
- a user in the root group, also as a supplementary group, counts as root;
- a passwd or group file larger than 1 MiB is not read: the image fails to be assessed, which refuses it.

The same holds for `docker run`, its audit, and compose.
"""

import pytest
from steps import (
    given_service,
    then_failed,
    then_generated_service,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    then_said,
    then_started_container,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.mark.parametrize(("tag", "problem"), [
    pytest.param("dockscreen-e2e/odd:named-user", "user 'app' is not defined in the image",
                 id="a user name without a passwd file"),
    pytest.param("dockscreen-e2e/odd:named-group", "group 'staff' is not defined in the image",
                 id="a group name without a group file"),
    pytest.param("dockscreen-e2e/odd:negative", "the image's user has a negative id", id="a negative id"),
])
def test_a_user_the_image_cannot_resolve_is_refused(world, odd_image, tag, problem):
    image, _ = odd_image(tag)
    when_dockscreen(world, "audit", image)
    then_refused(world, problem)
    then_said(world, f"image {image}: would be refused: {problem}")

    when_dockscreen(world, "run", image)
    then_refused(world, problem)
    then_nothing_handed_off(world)

    given_service(world, "app", image=image)
    when_dockscreen(world, "compose", "up")
    then_refused(world, f"service app: image {image}: {problem}")
    then_nothing_handed_off(world)


def test_numeric_ids_need_no_passwd_file(world, odd_image):
    image, free = odd_image("dockscreen-e2e/odd:numeric")
    when_dockscreen(world, "run", image)
    then_passed(world)
    assert then_started_container(world)["Config"]["User"] == f"{free}:{free}"


def test_a_uid_that_is_not_a_number_counts_as_root(world, odd_image):
    image, _ = odd_image("dockscreen-e2e/odd:garbled-uid")
    when_dockscreen(world, "audit", image)
    then_passed(world)
    then_said(world, "would run as uid 0 ",
              "; running as 65534:65534 instead of root")


def test_a_member_of_the_root_group_counts_as_root(world, odd_image):
    image, free = odd_image("dockscreen-e2e/odd:root-group")
    when_dockscreen(world, "audit", image)
    then_passed(world)
    then_said(world, f"would run as uid {free} ", "supplementary gids 0 ",
              "; running as 65534:65534 instead of root")

    given_service(world, "app", image=image)
    when_dockscreen(world, "compose", "up")
    then_passed(world)
    assert then_generated_service(world)["user"] == "65534:65534"


def test_a_passwd_file_too_large_to_read_fails_the_assessment(world, odd_image):
    image, _ = odd_image("dockscreen-e2e/odd:big-passwd")
    problem = "/etc/passwd in the image is larger than 1048576 bytes"
    when_dockscreen(world, "audit", image)
    then_failed(world, f"image {image}: could not be assessed: {problem}")

    when_dockscreen(world, "run", image)
    then_failed(world, problem, status=1)
    then_nothing_handed_off(world)

    given_service(world, "app", image=image)
    when_dockscreen(world, "compose", "audit")
    then_failed(world, f"service app: image {image}: {problem}")
