"""`docker buildx bake` through dockscreen, on the webapp's bake file, against the real docker.

A refused bake builds nothing, so these stay audits; the one that passes only runs the build checks.
"""

import pytest
from realdocker import ALPINE, require

pytestmark = pytest.mark.e2e


@pytest.fixture
def webapp(project, docker):
    require(docker("buildx", "version").status == 0, "docker buildx is not installed")
    return project("webapp")


def test_an_output_that_writes_to_the_host_is_refused_and_nothing_is_built(webapp, dockscreen):
    result = dockscreen("buildx", "bake", "dist", cwd=webapp)

    assert result.status == 1, result.output
    assert "target dist: output" in result.output and "writes to the host" in result.output
    assert not (webapp / "dist").exists()


def test_a_cache_secrets_and_the_ssh_agent_from_the_host_are_refused(webapp, dockscreen, tmp_path):
    # bake --print fails on a secret file that is not there, so they are put outside the project
    home = tmp_path / "home"
    (home / "cache").mkdir(parents=True)
    (home / ".npmrc").write_text("//registry.npmjs.org/:_authToken=not-a-token\n")
    env = {"BUILDKIT_CACHE": str(home / "cache"), "NPMRC": str(home / ".npmrc")}

    result = dockscreen("buildx", "bake", "ci", cwd=webapp, env=env)

    assert result.status == 1, result.output
    output = result.output
    assert "target ci: ssh forwards your SSH agent" in output
    assert "target ci: cache-to" in output
    assert "target ci: cache-from" in output
    assert "target ci: secret" in output


def test_a_bake_that_passes_is_handed_to_docker(webapp, docker, pulled, dockscreen):
    require("--call" in docker("buildx", "bake", "--help").stdout, "docker buildx bake has no --call")
    pulled(ALPINE)

    # --call check runs the Dockerfile's checks and builds nothing
    result = dockscreen("buildx", "bake", "--call", "check", "app", cwd=webapp)

    assert "✔ audit passed" in result.output
    assert result.status == 0, result.output
