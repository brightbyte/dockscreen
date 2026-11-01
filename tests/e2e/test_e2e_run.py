"""`dockscreen audit`, what `docker run` would do, against the real docker.

The images are alpine (root), nginx-unprivileged (USER 101), and the webapp's app image built with
your ids or with ids from a subordinate range.
"""

import pytest
from realdocker import (
    ALPINE,
    NGINX_UNPRIVILEGED,
    OWN_IDS_IMAGE,
    PROJECTS,
    SUBORDINATE_IMAGE,
    first_subordinate_id,
    group_exists,
    require,
    toml_string,
    user_exists,
)

pytestmark = pytest.mark.e2e


def build_app(docker, pulled, tag, uid, gid):
    """Builds the webapp's app image as tag, with its user's ids uid and gid."""
    pulled(ALPINE)
    built = docker("build", "--quiet", "--build-arg", f"UID={uid}", "--build-arg", f"GID={gid}", "--tag", tag,
                   str(PROJECTS / "webapp"))
    assert built.status == 0, built.stderr
    return tag


@pytest.fixture
def own_ids_image(docker, pulled, ordinary_ids):
    return build_app(docker, pulled, OWN_IDS_IMAGE, *ordinary_ids)


@pytest.fixture
def subordinate_image(docker, pulled):
    first = first_subordinate_id()
    require(first is not None, "/etc/subuid has no range")
    return build_app(docker, pulled, SUBORDINATE_IMAGE, first, first)


@pytest.fixture
def unprivileged(pulled):
    return pulled(NGINX_UNPRIVILEGED)


def test_a_root_image_runs_as_the_default_user(pulled, dockscreen, tmp_path):
    result = dockscreen("audit", pulled(ALPINE), cwd=tmp_path)

    assert result.status == 0, result.output
    assert f"image {ALPINE}: would run as uid 0 " in result.output
    assert "docker run would run it as the default user (65534:65534) instead" in result.output
    assert "docker run also adds" in result.output
    assert "✔ audit passed" in result.output


def test_what_the_command_line_asks_for_fails_the_audit_only_when_strict(pulled, dockscreen, tmp_path):
    args = ("-v", "/:/host", "--privileged", pulled(ALPINE), "true")

    lenient = dockscreen("audit", *args, cwd=tmp_path)
    strict = dockscreen("--strict-screen", "audit", *args, cwd=tmp_path)

    assert lenient.status == 0, lenient.output
    assert "command line: privileged is not allowed" in lenient.output
    assert "command line: bind mount '/' is outside" in lenient.output
    assert "--strict-screen makes them fail the audit" in lenient.output
    assert strict.status == 1, strict.output
    assert "⊖ denied by audit" in strict.output


def test_an_image_that_runs_as_you_needs_allow_me(own_ids_image, dockscreen, me, tmp_path):
    refused = dockscreen("audit", own_ids_image, cwd=tmp_path)
    allowed = dockscreen("--allow-me", "audit", own_ids_image, cwd=tmp_path)

    assert refused.status == 1, refused.output
    assert f"the image's uid {me[0]} is yours; pass --allow-me" in refused.output
    assert allowed.status == 0, allowed.output
    # the user is passed on as numbers, so docker reads nothing from the image's /etc/passwd
    assert f"docker run would create it again with --user={me[0]}:{me[1]}, as numbers" in allowed.output


def test_an_image_user_from_a_subordinate_range_is_refused(subordinate_image, dockscreen, tmp_path):
    result = dockscreen("audit", subordinate_image, cwd=tmp_path)

    assert result.status == 1, result.output
    assert "is in a subordinate id range of this host" in result.output


def test_choosing_the_user_on_the_command_line_skips_the_image_check(own_ids_image, dockscreen, tmp_path):
    result = dockscreen("audit", "--as-me", own_ids_image, cwd=tmp_path)

    assert result.status == 0, result.output
    assert "the user is set on the command line; the image's own user is not checked" in result.output


def test_an_image_user_that_is_a_local_account_is_refused(unprivileged, dockscreen, tmp_path):
    require(user_exists(101), "this host has no user 101, which nginx-unprivileged runs as")

    result = dockscreen("audit", unprivileged, cwd=tmp_path)

    assert result.status == 1, result.output
    assert "the image's uid 101 exists on this host (local user " in result.output


def test_an_image_user_outside_the_nobody_range_is_refused_with_mounts(unprivileged, dockscreen, tmp_path):
    require(not user_exists(101) and not group_exists(101),
            "this host has a user or group 101, which nginx-unprivileged runs as")
    site = tmp_path / "site"
    site.mkdir()

    without = dockscreen("audit", unprivileged, cwd=tmp_path)
    mounted = dockscreen("audit", "-v", f"{site}:/usr/share/nginx/html:ro", unprivileged, cwd=tmp_path)

    assert without.status == 0, without.output
    assert mounted.status == 1, mounted.output
    expected = "the image's uid 101 is not in the nobody range 65530-65534, and there are host mounts"
    assert expected in mounted.output


def test_an_image_section_allows_the_user_of_an_image_pulled_from_that_repository(unprivileged, dockscreen,
                                                                                  tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    config = f"[images.{toml_string('nginxinc/nginx-unprivileged')}]\nuser = \"101:101\"\n"

    result = dockscreen("audit", "-v", f"{site}:/usr/share/nginx/html:ro", unprivileged, cwd=tmp_path,
                        config=config)

    assert result.status == 0, result.output
    assert "runs as 101:101, the user the config file sets for it" in result.output


def test_an_image_that_is_not_there_fails_the_audit(docker, dockscreen, tmp_path):
    result = dockscreen("audit", "--brief", "--pull=never", "dockscreen-e2e/absent:1", cwd=tmp_path)

    assert result.status == 3, result.output
    assert result.last_line.startswith("✘ audit failed: docker could not create a container"), result.output


def test_an_audit_without_an_image_is_a_usage_error(docker, dockscreen, tmp_path):
    result = dockscreen("audit", cwd=tmp_path)

    assert result.status == 2, result.output
    assert "usage: dockscreen" in result.stderr
