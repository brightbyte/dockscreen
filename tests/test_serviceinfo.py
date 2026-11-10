import copy
import subprocess

import pytest
from fakes import FakeImages, id_facts, make_runtime, make_screener, marked, project_of, texts

from dockscreen.compose import serviceinfo
from dockscreen.host import config as configuration
from dockscreen.host.docker import DockerError
from dockscreen.model.origin import Origin
from dockscreen.screen import policy
from dockscreen.screen.finding import Verdict
from dockscreen.screen.notice import Notice
from dockscreen.screen.policy import Policy
from dockscreen.screen.rules import userrules
from dockscreen.screen.screener import Screener
from dockscreen.util import messages
from dockscreen.util.messages import GOOD, WARN

NOBODY = "65534:65534"

ROOT_FALLBACK = "running as 65534:65534 instead of root"
PIN = "user, image id and pull_policy: never fixed to what was checked, in the generated file only"
USER_HELP = userrules.USER_HELP
COMMAND = ["docker", "compose", "-f", "/gen/compose-0.yaml"]  # what prepare is given; only the tail matters


def project(**services):
    """A config whose services set no user unless told to."""
    return {"name": "proj", "services": {
        name: {"image": f"{name}:1", **fields} for name, fields in (services or {"web": {}}).items()}}


def prepare(config, images, args=(), active=("web",), codes=None, settings=None, chosen=frozenset()):
    screener, recorder = make_screener(images, active=active, codes=codes, reads=lambda _: config,
                                         screener=configured_screener(images, settings))
    found, failures = serviceinfo.prepare(COMMAND, project_of(config), list(args), screener, chosen)
    return screener.decide(project_of(config), found, failures), recorder, images


def configured_screener(images, settings=None):
    settings = settings or configuration.Config()
    return Screener(make_runtime(settings=settings, docker=images))


def subcommands(recorder):
    return [cmd[len(COMMAND):] for cmd in recorder.children]


# --- which services, and acquiring their images ---------------------------------

def test_services_to_run_are_the_active_ones_plus_those_named():
    config = project(web={}, db={}, debug={})
    screener, recorder = make_screener(active=("web", "db"))
    assert serviceinfo._services_to_run(COMMAND, config, ["-d", "debug", "--", "nope"], screener) == {
        "web", "db", "debug"}
    assert recorder.captured == [[*COMMAND, "config", "--services"]]


@pytest.mark.parametrize("policy_, present, pulled", [
    (None, False, True),          # the default is missing: pulled when absent
    (None, True, False),          # ... and left alone when there
    ("missing", False, True),
    ("if_not_present", True, False),
    ("always", True, True),       # updates keep happening
    ("daily", True, True),        # periodic policies: pulled every run, never stale
    ("weekly", True, True),
    ("every_12h", True, True),
    ("never", False, False),
])
def test_images_are_pulled_by_the_projects_pull_policy(policy_, present, pulled):
    fields = {"pull_policy": policy_} if policy_ else {}
    images = FakeImages(users={"web:1": "app"}, local={"web:1"} if present else set())

    prepared, recorder, _ = prepare(project(web=fields), images)

    assert subcommands(recorder) == ([["pull", "--", "web"]] if pulled else [])
    assert set(prepared.decisions) == {"web"}


def test_the_command_line_pull_policy_overrides_the_projects():
    images = FakeImages(users={"web:1": "app"})
    _, recorder, _ = prepare(project(web={"pull_policy": "never"}), images, ["--pull", "always"])
    assert subcommands(recorder) == [["pull", "--", "web"]]
    _, recorder, _ = prepare(project(web={"pull_policy": "always"}), images, ["--pull=never"])
    assert subcommands(recorder) == []


@pytest.mark.parametrize("fields, args, present, built", [
    ({}, [], False, True),                          # not there: built, as up would
    ({}, [], True, False),                          # there: used
    ({}, ["--build"], True, True),                  # up --build
    ({"pull_policy": "build"}, [], True, True),     # policy build: always rebuilt
    ({}, ["--no-build"], False, False),
])
def test_built_images_are_built_when_up_would_build_them(fields, args, present, built):
    config = project(web={"build": {"context": "/p"}, **fields})
    config["services"]["web"].pop("image")
    images = FakeImages(users={"proj-web": "app"}, local={"proj-web"} if present else set())

    _, recorder, _ = prepare(config, images, args)

    assert subcommands(recorder) == ([["build", "--", "web"]] if built else [])


def test_pulling_before_building_and_failure_stops_everything():
    config = project(web={}, app={"build": {"context": "/p"}})
    config["services"]["app"].pop("image")
    images = FakeImages(users={"web:1": "app", "proj-app": "app"}, local=set())
    _, recorder, _ = prepare(config, images, active=("web", "app"))
    assert subcommands(recorder) == [["pull", "--", "web"], ["build", "--", "app"]]

    prepared, recorder, images = prepare(config, FakeImages(users={}, local=set()), active=("web", "app"),
                                         codes={"pull": 1})
    assert texts(prepared.report.findings) == ["docker compose pull web failed"]
    # build never started
    assert prepared.decisions == {} and subcommands(recorder) == [["pull", "--", "web"]]
    assert images.calls == []  # and nothing was created


def test_listing_the_services_can_fail_closed():
    config = project()
    screener, _ = make_screener(reads=lambda _: config)
    capture = screener.docker.capture

    def failing_listing(cmd):
        if "--services" in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "boom")
        return capture(cmd)

    screener.docker.capture = failing_listing
    _, failures = serviceinfo.prepare(COMMAND, project_of(config), [], screener)
    assert texts(failures) == ["docker compose config --services failed"]


# --- deciding about the images ---------------------------------------------------

@pytest.mark.parametrize("image_user, replaces_root, refused", [
    ("app", False, False),       # 100000:100001, high and unknown to the host
    ("", True, False),           # no USER: root
    ("root", True, False),
    ("0:0", True, False),
    ("web", False, True),        # 1000: low, and the host has it
    ("ghost", False, True),      # not defined in the image
])
def test_the_images_own_user_is_judged_as_docker_run_does(image_user, replaces_root, refused):
    prepared, _, images = prepare(project(), FakeImages(users={"web:1": image_user}))

    decision = prepared.decisions["web"]
    assert (decision.replaces_root, decision.refused) == (replaces_root, refused)
    assert prepared.report.passed is not refused
    assert [call for call in images.calls if call[0] == "remove"] == [("remove", "c1")]  # nothing is left


def test_refusals_say_what_to_do():
    prepared, _, _ = prepare(project(), FakeImages(users={"web:1": "web"}))
    assert len(prepared.report.findings) == 1  # one line per service, however many ids are the problem
    refusal = str(prepared.report.findings[0])
    assert "service web: image web:1: the image's uid 1000 exists on this host" in refusal
    assert "gid 1000" in refusal
    assert prepared.report.findings[0].help == (
        f'set user: to choose one, or set user under [images."web"] in {make_runtime().config_file}')


def test_a_built_image_is_not_pointed_at_an_image_section():
    prepared, _, _ = prepare(project(web={"build": {"context": "."}}), FakeImages(users={"web:1": "web"}))
    assert prepared.report.findings[0].help == "set user: to choose one"  # the config file never applies


def test_services_with_a_user_are_not_looked_at():
    images = FakeImages(users={"web:1": ""})
    prepared, _, _ = prepare(project(web={"user": "1:1"}), images)
    assert prepared.decisions == {} and images.created == []


def test_only_started_services_are_looked_at_and_the_platform_is_passed():
    config = project(web={"platform": "linux/arm64"}, debug={})
    images = FakeImages(users={"web:1": "app", "debug:1": ""})
    prepared, _, _ = prepare(config, images, active=("web",))
    assert set(prepared.decisions) == {"web"}
    assert images.created == [("web:1", ["--pull=never", "--platform", "linux/arm64", "--", "web:1"])]


def test_an_image_that_is_not_there_is_a_failure():
    prepared, _, _ = prepare(project(web={"pull_policy": "never"}), FakeImages(users={}, local=set()))
    assert texts(prepared.report.findings) == ["service web: image web:1: the image is not available locally"]
    assert prepared.report.verdict is Verdict.FAILED  # no user would fix it


def test_inspection_errors_are_refusals_and_the_container_is_still_removed():
    images = FakeImages(users={"web:1": "app"})
    images.inspect_container = lambda ref: (_ for _ in ()).throw(DockerError("boom"))
    prepared, _, _ = prepare(project(), images)
    assert texts(prepared.decisions["web"].findings) == ["boom"] and prepared.decisions["web"].failed
    assert ("remove", "c1") in images.calls


# --- the config that runs ---------------------------------------------------------

def decided(config, images, active=("web",), settings=None, **kwargs):
    prepared, _, _ = prepare(config, images, active=active, settings=settings, **kwargs)
    changes = prepared.changes
    return prepared, changes.applied_to_definition(prepared.project.definition), changes.origins()


def user_origins(origins):
    return {name: keys["user"] for name, keys in origins.items() if "user" in keys}


def test_root_images_run_as_the_default_user_and_acceptable_ones_keep_their_own():
    config = project(web={}, db={}, user_set={"user": "7:7"})
    images = FakeImages(users={"web:1": "", "db:1": "app", "user_set:1": ""})

    _, final, origins = decided(config, images, active=("web", "db", "user_set"))

    services = final["services"]
    assert services["web"]["user"] == NOBODY
    assert services["db"]["user"] == "100000:100001"  # pinned as numbers
    assert services["user_set"]["user"] == "7:7"
    # the project's own user is not in it
    # no default_user configured: it is dockscreen's
    assert user_origins(origins) == {"web": Origin.DOCKSCREEN, "db": Origin.IMAGE}
    assert origins["db"]["pull_policy"] is Origin.DOCKSCREEN


def test_looked_at_images_are_pinned_in_the_generated_config_only():
    config = project(web={}, db={}, other={"user": "7:7"})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    original = copy.deepcopy(config)

    _, final, _ = decided(config, images, active=("web", "db", "other"))

    assert final["services"]["web"]["pull_policy"] == "never"
    assert final["services"]["db"]["pull_policy"] == "never"
    assert "pull_policy" not in final["services"]["other"]  # not looked at: the project's policy stands
    assert config == original                                # the input is untouched


def test_a_service_that_is_not_started_runs_as_the_default_user_in_case_it_is():
    config = project(web={}, debug={})
    _, final, origins = decided(config, FakeImages(users={"web:1": "app"}), active=("web",))
    assert final["services"]["debug"]["user"] == NOBODY
    assert "pull_policy" not in final["services"]["debug"]
    assert user_origins(origins) == {"debug": Origin.DOCKSCREEN, "web": Origin.IMAGE}


def test_the_final_config_passes_the_policy_with_the_users_where_they_come_from():
    config = project(web={}, db={}, debug={})
    for name in config["services"]:
        config["services"][name].update(cap_drop=["ALL"], security_opt=["no-new-privileges:true"])
    _, final, origins = decided(config, FakeImages(users={"web:1": "", "db:1": "app"}),
                                active=("web", "db"))
    policy = Policy(id_facts())

    assert policy.check_project(project_of(final, origins=origins)) == []
    # the config file is trusted: a configured user that the rules alone would refuse is only pointed out
    section = configuration.ConfigSection(user=(1000, 1000))
    settings = configuration.Config(images={"docker.io/library/db": section})
    images = FakeImages(users={"db:1": ""}, digests={"db:1": ["db@sha256:x"]})
    _, final, origins = decided(config, images, active=("db",), settings=settings)
    assert final["services"]["db"]["user"] == "1000:1000" and origins["db"]["user"] is Origin.CONFIG
    found = policy.check_project(project_of(final, origins=origins))
    assert found and {type(f) for f in found} == {Notice}
    problems = texts(policy.check_project(project_of(final)))
    assert [p for p in problems if p.startswith("service db: user")] == [
        "service db: user '1000:1000': uid 1000 exists on this host (local user daniel)",
        "service db: user '1000:1000': gid 1000 exists on this host (local group daniel)"]


def test_descriptions_and_notices():
    config = project(web={}, db={}, debug={}, set_={"user": "1:1"})
    images = FakeImages(users={"web:1": "", "db:1": "app"})
    prepared, _, _ = prepare(config, images, active=("web", "db", "set_"))

    assert marked(prepared.describe()) == [
        (f"{GOOD} service db: no user set; image db:1 runs as uid 100000 (no local user), gid 100001 "
         "(no local group); accepted"),
        (f"{messages.WARN} service debug: no user set and not started by default; dockscreen runs it "
         "as the default user (65534:65534) if it is started"),
        (f"{messages.WARN} service web: no user set; image web:1 would run as uid 0 (local user root), "
         f"gid 0 (local group root); {ROOT_FALLBACK}"),
        f"{messages.ROUTINE} services db, web: {PIN}",
    ]
    assert marked(prepared.notices()) == [
        f"{messages.WARN} service web: {ROOT_FALLBACK}",
        f"{messages.ROUTINE} services db, web: {PIN}"]


def test_a_refusal_names_the_local_account_that_the_images_id_would_be():
    refused, _, _ = prepare(project(web={}), FakeImages(users={"web:1": "web"}))
    assert texts(refused.report.findings) == [
        ("service web: image web:1: the image's uid 1000 exists on this host (local user daniel); "
         "the image's gid 1000 exists on this host (local group daniel)")]


# --- services with mounts ----------------------------------------------------------

BIND = {"volumes": [{"type": "bind", "source": "/p/data", "target": "/data"}]}


def test_with_mounts_an_image_user_outside_the_nobody_range_is_refused():
    prepared, _, _ = prepare(project(web=BIND), FakeImages(users={"web:1": "app"}))
    assert prepared.decisions["web"].refused
    assert "the image's uid 100000 is not in the nobody range 65530-65534" in str(prepared.report.findings[0])


def test_without_mounts_a_low_unknown_id_is_accepted_and_with_mounts_it_is_not():
    images = FakeImages(users={"web:1": "pg"})
    plain, _, _ = prepare(project(web={}), images)
    mounted, _, _ = prepare(project(web=BIND), images)
    assert plain.decisions["web"].origin is Origin.IMAGE and not plain.decisions["web"].refused
    assert mounted.decisions["web"].refused


def test_with_mounts_a_root_image_still_runs_as_the_default_user():
    config = project(web=BIND)
    _, final, _ = decided(config, FakeImages(users={"web:1": ""}))
    assert final["services"]["web"]["user"] == NOBODY


# --- users the config file sets ----------------------------------------------------

MARIADB = configuration.Config(
    images={"docker.io/library/mariadb": configuration.ConfigSection(user=(999, 999))})


def mariadb_project(**fields):
    return {"name": "proj", "services": {"db": {"image": "mariadb:11", **fields}}}


def test_a_configured_user_applies_to_an_image_pulled_from_that_repository():
    images = FakeImages(users={"mariadb:11": ""}, digests={"mariadb:11": ["mariadb@sha256:abc"]})
    prepared, final, origins = decided(mariadb_project(**BIND), images, active=("db",), settings=MARIADB)

    assert prepared.decisions["db"].origin is Origin.CONFIG and not prepared.decisions["db"].replaces_root
    assert final["services"]["db"]["user"] == "999:999" and user_origins(origins) == {"db": Origin.CONFIG}
    assert marked(prepared.notices()) == [  # configured: routine only, no surprise
        f"{messages.ROUTINE} services db: {PIN}"]
    assert marked(prepared.describe()) == [
        (f"{GOOD} service db: no user set; image mariadb:11 runs as 999:999, "
         "the user the config file sets for it"),
        f"{messages.ROUTINE} services db: {PIN}"]


@pytest.mark.parametrize("fields, digests, why", [
    ({}, [], "this image was not pulled from there"),                     # tagged locally
    ({}, ["evil.example/mariadb@sha256:abc"], "this image was not pulled from there"),
    ({"build": {"context": "."}}, ["mariadb@sha256:abc"], "the service builds its image"),
])
def test_a_configured_user_does_not_apply_to_an_image_that_only_has_the_name(fields, digests, why):
    images = FakeImages(users={"mariadb:11": ""}, digests={"mariadb:11": digests})
    config = mariadb_project(**fields)
    prepared, _, _ = prepare(config, images, active=("db",), settings=MARIADB)

    decision = prepared.decisions["db"]
    assert decision.replaces_root  # the normal rules: root runs as the default user
    lines = marked(prepared.describe())
    assert (f"{WARN} service db: note: the config has a section for docker.io/library/mariadb, "
            f"but {why}") in lines


def test_services_whose_user_the_command_line_chooses_are_not_decided():
    images = FakeImages(users={"web:1": "web"})  # would be refused
    prepared, _, _ = prepare(project(), images, chosen=frozenset({"web"}))
    assert prepared.report.passed and prepared.decisions == {}


def test_the_vetting_belongs_to_dockscreen_not_to_the_project():
    # No key in a compose file can mark a service as vetted: it lives in the Context only.
    config = project(web={"x-vetted": True, "vetted": True})
    problems = texts(policy.Policy(id_facts()).check_project(project_of(config)))
    assert "service web: key 'vetted' is not on the allow list" in problems
    assert "service web: user is not set, the image default may be root" in problems


def test_the_policy_decides_from_what_serviceinfo_saw():
    # serviceinfo looks at the images; the decision is the policy's: nothing here duplicates the rule
    screener, _ = make_screener(FakeImages(users={"web:1": ""}), reads=lambda _: project())
    found, _ = serviceinfo.prepare(COMMAND, project_of(project()), [], screener)
    prepared = screener.decide(project_of(project()), found)
    assert found and prepared.decisions == prepared.policy.assess_images(found.inspected)


def test_an_image_name_that_looks_like_an_option_is_not_read_as_one():
    images = FakeImages(users={"-x": "app"})
    prepare(project(web={"image": "-x"}), images)
    assert images.created[0][1][-2:] == ["--", "-x"]


def test_the_default_user_that_replaces_root_gets_a_home_unless_the_service_sets_one():
    config = project(web={}, db={"environment": {"HOME": "/srv", "X": "1"}}, app={})
    images = FakeImages(users={"web:1": "", "db:1": "", "app:1": "app"})

    _, final, _ = decided(config, images, active=("web", "db", "app"))

    services = final["services"]
    assert services["web"]["environment"] == {"HOME": "/tmp"}
    assert services["db"]["environment"] == {"HOME": "/srv", "X": "1"}
    assert "environment" not in services["app"]  # its own user: docker finds its home in passwd


def test_a_service_that_is_not_started_gets_the_default_users_home_too():
    _, final, _ = decided(project(web={}, idle={}), FakeImages(users={"web:1": "app"}), active=("web",))
    assert final["services"]["idle"]["environment"] == {"HOME": "/tmp"}


def test_the_default_home_follows_the_config_file_and_may_be_left_out():
    images = FakeImages(users={"web:1": ""})
    _, final, _ = decided(project(web={}), images, settings=configuration.Config(default_home="/var/empty"))
    assert final["services"]["web"]["environment"] == {"HOME": "/var/empty"}
    _, final, _ = decided(project(web={}), images, settings=configuration.Config(default_home=""))
    assert "environment" not in final["services"]["web"]


def test_root_as_the_default_user_gets_no_home():
    settings = configuration.Config(default_user=(0, 0))
    _, final, _ = decided(project(web={}), FakeImages(users={"web:1": ""}), settings=settings)
    assert "environment" not in final["services"]["web"]


def test_a_looked_at_image_is_pinned_by_id_so_a_moved_tag_cannot_change_what_runs():
    config = project(web={}, db={}, other={"user": "7:7"}, built={"build": {"context": "."}})
    images = FakeImages(users={"web:1": "app", "db:1": "", "other:1": "app", "proj-built": "app"})
    original = copy.deepcopy(config)
    config["services"]["built"].pop("image")  # a built service has no image: compose names it itself

    _, final, _ = decided(config, images, active=("web", "db", "built"))

    services = final["services"]
    assert services["web"]["image"] == FakeImages.image_id("web:1")
    assert services["db"]["image"] == FakeImages.image_id("db:1")  # the fallback pins it too
    assert services["other"]["image"] == "other:1"                  # not looked at: the project's name
    assert "image" not in services["built"] and services["built"]["pull_policy"] == "never"
    assert original["services"]["web"]["image"] == "web:1"
