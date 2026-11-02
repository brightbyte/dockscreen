"""Feature: `docker buildx bake` builds only what cannot reach the host

Rules (docker_bake), on the definition that `bake --print` gives with the command line applied:
- build contexts, Dockerfiles and named contexts are inside the current directory;
- no host network, no entitlements, no SSH agent;
- outputs stay in the image store or a registry, cache-to goes inline or to a registry, a local cache-from
  is inside the current directory;
- secrets are files inside the current directory, never variables;
- a key that is not known is refused; --print and --help pass on unchecked.

A refused bake builds nothing; the one that passes is held back before it builds.
"""

import pytest
from realdocker import ALPINE, require
from steps import (
    given_example_project,
    given_file,
    given_image,
    given_outside_dir,
    then_failed,
    then_handed_off,
    then_handed_off_unchanged,
    then_nothing_handed_off,
    then_passed,
    then_refused,
    when_dockscreen,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def bakefile(world):
    """Returns given(target body), which writes a docker-bake.hcl with one target, `app`, set up so."""
    require(world.docker("buildx", "version").status == 0, "docker buildx is not installed")
    given_file(world, "Dockerfile", f"FROM {ALPINE}\n")

    def given(body: str) -> None:
        given_file(world, "docker-bake.hcl", f'target "app" {{\n  context = "."\n{body}\n}}\n')
    return given


# buildx prints some entries as text and newer ones as objects, so the problems are matched in parts
@pytest.mark.parametrize(("body", "problem"), [
    pytest.param('  output = ["type=local,dest=out"]', ["output ", "writes to the host"],
                 id="a local output"),
    pytest.param('  output = ["type=tar,dest=out.tar"]', ["output ", "writes to the host"],
                 id="a tar output"),
    pytest.param('  output = ["type=docker,dest=out.tar"]', ["output ", "writes to the host"],
                 id="an image written to a file"),
    pytest.param('  cache-to = ["type=local,dest=cache"]', ["cache-to ", "writes to the host"],
                 id="a local cache export"),
    pytest.param('  cache-from = ["type=local,src=/etc"]', ["cache-from ", "is outside"],
                 id="a local cache outside"),
    pytest.param('  network = "host"', ["network 'host' is not allowed"], id="host network"),
    pytest.param('  entitlements = ["network.host"]',
                 ["entitlements ask for access beyond the build sandbox"],
                 id="entitlements"),
    pytest.param('  ssh = ["default"]', ["ssh forwards your SSH agent and is not allowed"],
                 id="the SSH agent"),
    pytest.param('  secret = ["id=home,env=HOME"]', ["secret ", "copies a variable or cannot be read"],
                 id="a variable"),
    pytest.param('  secret = ["id=host,src=/etc/hostname"]', ["secret ", "is outside"],
                 id="a secret file outside"),
    pytest.param('  contexts = { etc = "/etc" }', ["contexts 'etc': '/etc' is outside"],
                 id="a named context outside"),
    pytest.param('  dockerfile = "../Dockerfile"', ["dockerfile '../Dockerfile' is outside"],
                 id="a Dockerfile outside"),
])
def test_a_target_that_reaches_the_host_is_refused(world, bakefile, body, problem):
    bakefile(body)
    when_dockscreen(world, "buildx", "bake", "app")
    then_refused(world, f"target app: {problem[0]}", *problem[1:])
    then_nothing_handed_off(world)


def test_a_context_outside_the_current_directory_is_refused(world, bakefile):
    outside = given_outside_dir(world)
    bakefile("")
    (world.project_dir / "docker-bake.hcl").write_text(f'target "app" {{\n  context = "{outside}"\n}}\n')
    when_dockscreen(world, "buildx", "bake", "app")
    then_refused(world, f"target app: context '{outside}' is outside {world.project_dir}")


def test_the_command_line_is_applied_before_the_check(world, bakefile):
    bakefile("")
    when_dockscreen(world, "buildx", "bake", "--set", "app.output=type=local,dest=out", "app")
    then_refused(world, "target app: output")
    then_nothing_handed_off(world)


@pytest.mark.parametrize("body", [
    pytest.param("", id="plain"),
    pytest.param('  output = ["type=docker"]', id="into the image store"),
    pytest.param('  cache-to = ["type=inline"]\n  cache-from = ["type=local,src=cache"]', id="caches"),
    pytest.param('  secret = ["id=token,src=token.txt"]', id="a secret of the project"),
])
def test_a_target_that_stays_in_the_build_is_handed_to_docker(world, bakefile, body):
    given_file(world, "token.txt", "not-a-secret")
    given_file(world, "cache/.keep")
    bakefile(body)
    when_dockscreen(world, "buildx", "bake", "app")
    then_passed(world)
    then_handed_off_unchanged(world, "buildx", "bake", "app")


@pytest.mark.parametrize("args", [["--print"], ["--help"]])
def test_print_and_help_pass_on_unchecked(world, bakefile, args):
    bakefile('  network = "host"')
    when_dockscreen(world, "buildx", "bake", *args, "app")
    assert [c.argv for c in world.calls] == [["buildx", "bake", *args, "app"]], world.report()
    assert "denied" not in world.output


def test_a_bake_file_that_cannot_be_read_fails(world, bakefile):
    given_file(world, "docker-bake.hcl", "target {\n")
    when_dockscreen(world, "buildx", "bake")
    then_failed(world, "docker buildx bake --print failed", status=1)
    then_nothing_handed_off(world)


def test_the_example_webapp_is_refused_for_each_way_it_reaches_the_host(world, bakefile):
    given_example_project(world, "webapp")
    when_dockscreen(world, "buildx", "bake", "dist")
    then_refused(world, "target dist: output", "writes to the host")
    assert not (world.project_dir / "dist").exists()

    home = given_outside_dir(world, "home")
    (home / "cache").mkdir()
    (home / ".npmrc").write_text("//registry.npmjs.org/:_authToken=not-a-token\n")
    world.env.update(BUILDKIT_CACHE=str(home / "cache"), NPMRC=str(home / ".npmrc"))
    when_dockscreen(world, "buildx", "bake", "ci")
    then_refused(world, "target ci: ssh forwards your SSH agent", "target ci: cache-to",
                 "target ci: cache-from", "target ci: secret")


def test_a_check_call_is_handed_to_docker(world, bakefile):
    require("--call" in world.docker("buildx", "bake", "--help").stdout, "docker buildx bake has no --call")
    given_image(world, ALPINE)
    given_example_project(world, "webapp")
    when_dockscreen(world, "buildx", "bake", "--call", "check", "app")
    then_passed(world)
    then_handed_off(world, "--call", "check", "app")
