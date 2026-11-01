"""`dockscreen compose audit` on the example projects, against the real docker.

webapp: an app built from a Dockerfile with the developer's ids, a cache and a web server from pulled
images, a debug service behind a profile, and an override for debugging that asks for too much.
monitoring: cAdvisor and the node exporter, which read the host as their documentation sets them up.
"""

import json
import re

import pytest
from realdocker import ALPINE, NGINX, REDIS, WEBAPP_APP, toml_string

pytestmark = pytest.mark.e2e


@pytest.fixture
def webapp(project):
    return project("webapp")


@pytest.fixture
def webapp_images(pulled, ordinary_ids):
    """Pulls what the webapp needs: a registry out of reach skips the tests instead of failing them."""
    for image in (ALPINE, REDIS, NGINX):
        pulled(image)


@pytest.fixture
def monitoring(project):
    return project("monitoring")


def test_the_webapp_passes_with_allow_me_and_says_what_it_changes(webapp, webapp_images, dockscreen, me):
    result = dockscreen("--allow-me", "compose", "audit", cwd=webapp, env={"TZ": "Europe/Berlin"})

    assert result.status == 0, result.output
    output = result.output
    # the image is built with your ids, which --allow-me allows, bind mount of ./src included
    assert f"service app: no user set; image {WEBAPP_APP} runs as uid {me[0]} " in output
    # redis and nginx start as root
    assert "service cache: no user set; running as 65534:65534 instead of root" in output
    assert "service web: no user set; running as 65534:65534 instead of root" in output
    # behind a profile: not pulled, but said what would happen
    assert "service mailpit: no user set and not started by default" in output
    assert "service app: environment variables taken from your shell: TZ" in output
    assert "cap_drop" in output and "no-new-privileges" in output
    assert "✔ audit passed" in output


def test_an_image_that_runs_as_you_is_refused_without_allow_me(webapp, webapp_images, dockscreen, me):
    result = dockscreen("compose", "audit", cwd=webapp)

    assert result.status == 1, result.output
    expected = f"service app: image {WEBAPP_APP}: the image's uid {me[0]} is yours; pass --allow-me"
    assert expected in result.output
    assert "⊖ denied by audit" in result.output


def test_a_static_dir_from_dotenv_outside_the_project_is_refused_before_anything_is_pulled(webapp,
                                                                                         dockscreen):
    (webapp / ".env").write_text("STATIC_DIR=/etc\n")

    result = dockscreen("--allow-me", "compose", "audit", cwd=webapp)

    assert result.status == 1, result.output
    assert "service web: bind mount '/etc' is outside" in result.output
    assert "nothing was pulled or built" in result.output


def test_a_symlink_in_the_project_is_followed_out_of_it(webapp, dockscreen):
    (webapp / "static" / "index.html").unlink()
    (webapp / "static").rmdir()
    (webapp / "static").symlink_to("/etc")

    result = dockscreen("--allow-me", "compose", "audit", cwd=webapp)

    assert result.status == 1, result.output
    assert re.search(r"service web: bind mount '[^']*static' is outside", result.output), result.output


def test_mount_dirs_of_the_project_allow_a_static_dir_outside_it(webapp, webapp_images, dockscreen, tmp_path):
    site = tmp_path / "site"
    site.mkdir()
    env = {"STATIC_DIR": str(site)}

    refused = dockscreen("--allow-me", "compose", "audit", cwd=webapp, env=env)
    config = f"[projects.{toml_string(str(webapp))}]\nmount_dirs = [{toml_string(str(site))}]\n"
    allowed = dockscreen("--allow-me", "compose", "audit", cwd=webapp, env=env, config=config)

    assert refused.status == 1, refused.output
    assert f"service web: bind mount '{site}' is outside" in refused.output
    assert "add a directory that contains it to mount_dirs under [projects." in refused.output
    assert allowed.status == 0, allowed.output


def test_an_image_section_sets_the_user_of_an_image_pulled_from_that_repository(webapp, webapp_images,
                                                                                dockscreen):
    config = '[images."redis"]\nuser = "999:999"\n'

    result = dockscreen("--allow-me", "compose", "audit", cwd=webapp, config=config)

    assert result.status == 0, result.output
    assert (f"service cache: no user set; image {REDIS} runs as 999:999, the user the config file sets for it"
            in result.output)


def test_the_debug_override_is_refused_for_each_way_it_reaches_beyond_the_container(webapp, dockscreen):
    result = dockscreen("--allow-me", "compose", "-f", "compose.yaml", "-f", "compose.debug.yaml", "audit",
                        cwd=webapp)

    assert result.status == 1, result.output
    output = result.output
    assert "service app: cap_add is not allowed" in output
    assert "service app: security_opt 'seccomp=unconfined' is not allowed" in output
    assert "service app: bind mount '/var/run/docker.sock' is outside" in output
    assert "nothing was pulled or built" in output


def test_the_monitoring_stack_is_refused_for_each_way_it_reaches_the_host(monitoring, dockscreen):
    result = dockscreen("compose", "audit", cwd=monitoring)

    assert result.status == 1, result.output
    output = result.output
    for problem in [
        "service cadvisor: privileged is not allowed",
        "service cadvisor: devices is not allowed",
        "service cadvisor: bind mount '/' is outside",
        "service cadvisor: bind mount '/sys' is outside",
        "service node-exporter: pid: host shares a namespace outside the project",
        "service node-exporter: network_mode: host shares a namespace outside the project",
        "service node-exporter: bind mount '/' is outside",
    ]:
        assert problem in output
    assert "nothing was pulled or built" in output
    assert "harden" in output  # the hint at the subcommand that fixes what it can


def test_brief_prints_only_the_verdict_with_the_first_reason(monitoring, dockscreen):
    result = dockscreen("compose", "audit", "--brief", cwd=monitoring)

    assert result.status == 1, result.output
    assert result.stdout.count("\n") == 1, result.stdout
    assert re.fullmatch(r"⊖ denied by audit: service \S+: .* \(\+\d+ more\)", result.last_line), result.stdout


def test_the_audit_fails_when_the_compose_file_cannot_be_read(webapp, dockscreen):
    (webapp / "compose.yaml").write_text(json.dumps({"services": {"app": {"image": ALPINE, "volumes": 3}}}))

    result = dockscreen("compose", "audit", cwd=webapp)

    assert result.status == 3, result.output
    assert "✘ audit failed" in result.output



def test_harden_fixes_the_debug_override_so_that_the_audit_passes(webapp, webapp_images, dockscreen):
    # the images are local already (webapp_images), so harden pulls nothing and only builds the app
    debug = ("compose", "-f", "compose.yaml", "-f", "compose.debug.yaml")

    hardened = dockscreen(*debug, "harden", cwd=webapp)
    (webapp / "compose.harden.yaml").write_text(hardened.stdout)
    audited = dockscreen("--allow-me", *debug, "-f", "compose.harden.yaml", "audit", cwd=webapp)

    assert hardened.status == 0, hardened.output
    patch = hardened.stdout
    assert "cap_add: !reset null" in patch
    assert "security_opt: !override [" in patch and "seccomp" not in patch
    assert "mount source /var/run/docker.sock was replaced by the placeholder ./VAR_RUN_DOCKER.SOCK" in patch
    assert "user:" not in patch  # the app runs as you, which harden allows as --allow-me would
    assert audited.status == 0, audited.output
