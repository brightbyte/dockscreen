import pytest
from fakes import FakeDocker, make_runtime

from dockscreen import argscan, config, imagedecision
from dockscreen.dockerclient import _first_file_of_tar
from dockscreen.run import gate

DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]


def runtime(docker, settings=None):
    """The Runtime of a `docker` command line run with docker and settings, by the caller fakes.ME."""
    return make_runtime(docker=docker, settings=settings or config.Config())


def test_acceptable_image_user_runs_attached_with_hardening_defaults():
    docker = FakeDocker(image_user="app", command=["echo"], open_stdin=True)

    assert gate.run([], ["-i", "img", "echo"], runtime(docker)) == 42  # the container's exit code

    assert docker.calls[0] == ("create", [*DEFAULTS, "-i", "img", "echo"])
    assert docker.calls[-1] == ("start", "cid1", True, True, None)


def test_detached_run_starts_without_attaching():
    docker = FakeDocker(image_user="app")
    gate.run([], ["-d", "--detach-keys=ctrl-x", "img"], runtime(docker))
    assert docker.calls[0][1][-1] == "img" and "-d" not in docker.calls[0][1]
    assert docker.calls[-1] == ("start", "cid1", False, False, "ctrl-x")


def test_an_image_choosing_a_user_the_host_has_is_refused_and_the_container_removed(capsys):
    docker = FakeDocker(image_user="web")  # uid 1000: the host has an account with that id

    assert gate.run([], ["img"], runtime(docker)) == 1

    err = capsys.readouterr().err
    assert "the image's uid 1000 exists on this host (local user daniel)" in err
    assert "pass --user" not in err  # what to do about it is for helpful mode
    assert docker.names() == ["create", "inspect", "remove"]  # never started


@pytest.mark.parametrize("image_user, ids", [
    ("pg", "998:998"), ("998", "998:998"), ("app", "100000:100001"), ("424242:7", "424242:7")])
def test_without_mounts_the_images_own_non_root_user_is_kept_whatever_its_id(image_user, ids, capsys):
    docker = FakeDocker(image_user=image_user)
    assert gate.run([], ["img"], runtime(docker)) == 42
    assert f"--user={ids}" in docker.calls[3][1]  # the second create: pinned
    assert "nobody" not in capsys.readouterr().err


def test_an_accepted_image_user_is_pinned_as_numbers_so_the_runtime_resolves_nothing():
    docker = FakeDocker(image_user="app")

    assert gate.run([], ["img"], runtime(docker)) == 42

    # created as the image has it, checked, removed, and created again with the checked ids
    assert docker.names() == ["create", "inspect", "remove", "create", "inspect", "start"]
    assert "--user=100000:100001" not in docker.calls[0][1]
    assert docker.calls[3][1] == [*DEFAULTS, "--user=100000:100001", "img"]
    assert docker.calls[-1][:2] == ("start", "cid1")


# --- mounts: the user must be chosen explicitly --------------------------------------

BIND = {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]}


@pytest.mark.parametrize("extra", [
    BIND,
    {"HostConfig": {"Binds": ["/p:/p:ro"]}},
    {"HostConfig": {"Mounts": [{"Type": "bind"}]}},
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_has_host_mounts(extra):
    assert imagedecision._has_host_mounts({"Config": {}, **extra})


@pytest.mark.parametrize("extra", [
    {},
    {"Mounts": [{"Type": "volume", "Name": "data"}, {"Type": "tmpfs"}]},
    {"HostConfig": {"Binds": ["data:/var/lib/data"], "Devices": [], "VolumesFrom": None}},
])
def test_named_volumes_and_tmpfs_are_not_host_mounts(extra):
    assert not imagedecision._has_host_mounts({"Config": {}, **extra})


def test_with_a_bind_mount_an_image_user_outside_the_nobody_range_is_refused(capsys):
    docker = FakeDocker(image_user="pg", info_extra=BIND)

    assert gate.run([], ["-v", "/p:/p", "img"], runtime(docker)) == 1

    assert docker.names() == ["create", "inspect", "remove"]
    err = capsys.readouterr().err
    assert "the image's uid 998 is not in the nobody range 65530-65534, and there are host mounts" in err


@pytest.mark.parametrize("extra", [
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_devices_and_volumes_from_count_as_mounts(extra, capsys):
    docker = FakeDocker(image_user="app", info_extra=extra)
    assert gate.run([], ["img"], runtime(docker)) == 1
    assert "not in the nobody range" in capsys.readouterr().err


def test_named_volumes_are_not_host_mounts(capsys):
    docker = FakeDocker(image_user="app", info_extra={"Mounts": [{"Type": "volume", "Name": "data"}]})
    assert gate.run([], ["img"], runtime(docker)) == 42
    assert "--user=100000:100001" in docker.calls[3][1]


def test_an_image_that_is_already_nobody_is_accepted_with_mounts():
    docker = FakeDocker(image_user="nobody", info_extra=BIND)
    assert gate.run([], ["img"], runtime(docker)) == 42
    assert "--user=65534:65534" in docker.calls[3][1]


def test_a_user_on_the_command_line_is_all_a_mounting_container_needs(capsys):
    docker = FakeDocker(image_user="pg", container_user="998:998", info_extra=BIND)
    assert gate.run([], ["--user", "998:998", "-v", "/p:/p", "img"], runtime(docker)) == 42
    assert docker.names().count("create") == 1
    # no notice about the user, which was chosen on the command line
    assert capsys.readouterr().err.splitlines()[1:] == ["[dockscreen] \u2714 audit passed"]


def test_root_with_mounts_runs_as_the_default_user(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND)
    assert gate.run([], ["img"], runtime(docker)) == 42
    assert "running as 65534:65534 instead of root" in (
        capsys.readouterr().err)


def created_env(docker):
    """The environment arguments of the last create."""
    args = [call for call in docker.calls if call[0] == "create"][-1][1]
    return [args[i + 1] for i, arg in enumerate(args) if arg == "-e"]


@pytest.mark.parametrize("image_env", [[], ["HOME=/root"]])
def test_the_default_user_that_replaces_root_gets_a_home_it_can_write_to(image_env):
    docker = FakeDocker(image_user="", image_env=image_env)
    assert gate.run([], ["img"], runtime(docker)) == 42
    assert created_env(docker) == ["HOME=/tmp"]  # also over the image's own HOME, which is root's


@pytest.mark.parametrize("docker, args", [
    (FakeDocker(image_user="", image_env=["HOME=/root"]), ["-e", "HOME=/srv", "img"]),
    (FakeDocker(image_user="", image_env=["HOME=/root"], env_file=["HOME=/srv"]), ["--env-file", "f", "img"]),
])
def test_a_home_chosen_on_the_command_line_or_in_an_env_file_stays(docker, args):
    assert gate.run([], args, runtime(docker)) == 42
    assert "HOME=/tmp" not in created_env(docker)


def test_the_default_home_comes_from_the_config_file_and_may_be_left_out():
    docker = FakeDocker(image_user="")
    assert gate.run([], ["img"], runtime(docker, config.Config(default_home="/var/empty"))) == 42
    assert created_env(docker) == ["HOME=/var/empty"]
    left_alone = FakeDocker(image_user="", image_env=["HOME=/root"])
    assert gate.run([], ["img"], runtime(left_alone, config.Config(default_home=""))) == 42
    assert created_env(left_alone) == []


def test_an_image_section_can_choose_the_home_of_the_default_user():
    settings = config.Config(images={"docker.io/library/img": config.Section(default_home="/work")})
    docker = FakeDocker(image_user="", repo_digests=["img@sha256:abc"])
    assert gate.run([], ["img"], runtime(docker, settings)) == 42
    assert created_env(docker) == ["HOME=/work"]


def test_only_a_default_user_replacing_root_gets_a_home():
    accepted = FakeDocker(image_user="app")  # the image's own user: docker finds its home in passwd
    assert gate.run([], ["img"], runtime(accepted)) == 42
    assert created_env(accepted) == []
    root_default = FakeDocker(image_user="")
    assert gate.run([], ["img"], runtime(root_default, config.Config(default_user=(0, 0)))) == 42
    assert created_env(root_default) == []  # root has a home of its own


def test_run_says_it_adds_the_defaults_as_a_routine_change(capsys):
    docker = FakeDocker(image_user="app")
    assert gate.run([], ["img"], runtime(docker)) == 42
    err = capsys.readouterr().err
    assert "added --cap-drop=ALL --security-opt=no-new-privileges:true" in err


def test_what_to_do_about_the_default_user_is_for_helpful_mode(capsys, helpful):
    assert gate.run([], ["img"], runtime(FakeDocker(image_user=""))) == 42
    assert "pass --user UID:GID, --as NAME or --as-me to choose a user" in capsys.readouterr().err


def test_forcing_root_to_the_default_user_is_marked_check_this(capsys):
    docker = FakeDocker(image_user="")
    assert gate.run([], ["img"], runtime(docker)) == 42
    assert "running as 65534:65534 instead of root" in (
        capsys.readouterr().err)


def test_the_default_user_comes_from_the_config_file(capsys):
    docker = FakeDocker(image_user="")
    assert gate.run([], ["img"], runtime(docker, config.Config(default_user=(4000, 4001)))) == 42
    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=4000:4001"]
    assert "running as 4000:4001 instead of root" in capsys.readouterr().err


def test_a_root_default_user_is_announced_on_every_run(capsys):
    docker = FakeDocker(image_user="app")
    gate.run([], ["img"], runtime(docker, config.Config(default_user=(0, 0))))
    assert "the configured default user is 0:0" in capsys.readouterr().err


# --- users the config file sets for an image repository -----------------------------

IMG_USERS = config.Config(images={"docker.io/library/img": config.Section(user=(999, 999))})


def test_a_configured_image_user_replaces_the_images_own(capsys):
    docker = FakeDocker(image_user="", info_extra=BIND, repo_digests=["img@sha256:abc"])

    assert gate.run([], ["img"], runtime(docker, IMG_USERS)) == 42

    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=999:999"]  # root included, mounts or not
    err = capsys.readouterr().err
    assert "would run as root" not in err  # the config file chose the user: routine, not a surprise
    assert "image img runs as 999:999, passed to docker as numbers" in err


def test_a_configured_user_needs_the_image_to_have_been_pulled_from_that_repository(capsys):
    docker = FakeDocker(image_user="", repo_digests=["evil.example/img@sha256:abc"])
    assert gate.run([], ["img"], runtime(docker, IMG_USERS)) == 42
    assert "--user=65534:65534" in docker.calls[3][1]  # an image tagged img locally: the normal rules


# --- --allow-me ------------------------------------------------------------------

def test_an_image_whose_user_is_the_caller_needs_allow_me(capsys):
    docker = FakeDocker(image_user="4242:4343")
    assert gate.run([], ["img"], runtime(docker)) == 1
    assert "the image's uid 4242 is yours; pass --allow-me to allow it" in capsys.readouterr().err

    docker = FakeDocker(image_user="4242:4343")
    assert gate.run([], ["--allow-me", "img"], runtime(docker)) == 42
    assert docker.calls[0][1] == [*DEFAULTS, "img"]  # --allow-me is dockscreen's, not docker's
    assert docker.calls[3][1][:3] == [*DEFAULTS, "--user=4242:4343"]


def test_allow_me_applies_with_mounts_too():
    docker = FakeDocker(image_user="4242:4343", info_extra=BIND)
    assert gate.run([], ["img"], runtime(docker), allow_me=True) == 42


@pytest.mark.parametrize("image_user", ["", "root", "0:0", "424242"])  # the last gets gid 0: no passwd entry
def test_an_image_that_would_run_as_root_is_run_as_nobody_instead(image_user, capsys):
    docker = FakeDocker(image_user=image_user, open_stdin=True)

    assert gate.run([], ["-i", "img"], runtime(docker)) == 42

    creates = [call[1] for call in docker.calls if call[0] == "create"]
    assert creates == [[*DEFAULTS, "-i", "img"],
                       [*DEFAULTS, "--user=65534:65534", "-e", "HOME=/tmp", "-i", "img"]]
    assert docker.names().count("remove") == 1
    assert docker.calls[docker.names().index("remove")] == ("remove", "cid1")
    assert docker.calls[-1] == ("start", "cid1", True, True, None)
    err = capsys.readouterr().err
    assert "running as 65534:65534 instead of root" in err


@pytest.mark.parametrize("flags", [
    ["--user", "1000:1000"], ["-u", "0:0"], ["--user=0:0"], ["--as-me"], ["--as", "alice"],
])
def test_a_user_on_the_command_line_prevents_the_fallback(flags, capsys):
    docker = FakeDocker(image_user="")  # root, which would fall back without the flag
    assert gate.run([], [*flags, "img"], runtime(docker)) == 42

    assert docker.names().count("create") == 1
    assert "default user" not in capsys.readouterr().err


def test_as_me_means_the_callers_ids():
    docker = FakeDocker(image_user="")
    gate.run([], ["--as-me", "img"], runtime(docker))
    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]


def test_failure_to_create_the_fallback_container_is_passed_on():
    docker = FakeDocker(image_user="")
    creates = iter([(0, "cid1"), (125, None)])
    docker.create = lambda args: next(creates)
    assert gate.run([], ["img"], runtime(docker)) == 125


def test_a_user_on_the_command_line_is_trusted():
    docker = FakeDocker(image_user="", container_user="1000:1000")
    assert gate.run([], ["--user", "1000:1000", "img"], runtime(docker)) == 42
    assert "remove" not in docker.names()


def test_existing_containers_cannot_be_rewritten_so_a_root_image_is_refused():
    docker = FakeDocker(image_user="")
    problems = gate.check_existing([], ["c1"], runtime(docker))
    assert problems == [
        "c1: cannot change the user of an existing container; it would run as the image's user, "
        "not as 65534:65534"]
    assert problems[0].help == "recreate it with --user 65534:65534"


def test_an_existing_container_already_running_as_the_pinned_user_is_accepted():
    # the image names the same numbers, so the container's user is not seen as an explicit choice
    pulled = ["img@sha256:abc"]
    docker = FakeDocker(image_user="999:999", repo_digests=pulled)
    assert gate.check_existing([], ["c1"], runtime(docker, IMG_USERS)) == []
    other = FakeDocker(image_user="998:998", repo_digests=pulled)
    assert gate.check_existing([], ["c1"], runtime(other, IMG_USERS))


def test_an_existing_container_with_mounts_follows_the_mount_rule_too():
    docker = FakeDocker(image_user="app", info_extra=BIND)
    problems = gate.check_existing([], ["c1"], runtime(docker))
    assert problems and all("not in the nobody range" in p for p in problems)
    assert gate.check_existing([], ["c1"], runtime(FakeDocker(image_user="app"))) == []  # no mounts: fine


def test_user_unknown_to_the_image_is_refused(capsys):
    docker = FakeDocker(image_user="ghost")
    assert gate.run([], ["img"], runtime(docker)) == 1
    assert "not defined in the image" in capsys.readouterr().err


def test_misread_command_line_is_refused_and_cleaned_up(capsys):
    docker = FakeDocker(image_user="app", image="something-else")
    assert gate.run([], ["img"], runtime(docker)) == 1
    assert "could not reliably tell the image" in capsys.readouterr().err
    assert docker.names()[-1] == "remove"

    docker = FakeDocker(image_user="app", command=["different"])
    assert gate.run([], ["img", "ls", "-d"], runtime(docker)) == 1


def test_create_failure_is_passed_on():
    docker = FakeDocker(create_code=125)
    assert gate.run([], ["img"], runtime(docker)) == 125
    assert docker.names() == ["create"]


def test_unreadable_command_line_is_refused(capsys):
    assert gate.run([], ["--name"], runtime(FakeDocker())) == 1
    assert "cannot read the command line" in capsys.readouterr().err


@pytest.mark.parametrize("args, refs", [
    (["a", "b"], ["a", "b"]),
    (["-a", "-i", "a"], ["a"]),
    (["--detach-keys", "x", "a", "--attach"], ["a"]),
    (["--detach-keys=x", "a"], ["a"]),
    (["-t", "5", "a"], ["a"]),
    (["--time=5", "a", "--", "-weird"], ["a", "-weird"]),
])
def test_container_refs(args, refs):
    assert argscan.positionals(args, gate.VALUE_LONG, gate.VALUE_SHORT) == refs


def test_existing_containers_are_checked_by_the_same_rule():
    ok = FakeDocker(image_user="app")
    assert gate.check_existing([], ["web1"], runtime(ok)) == []
    bad = FakeDocker(image_user="web")
    problems = gate.check_existing([], ["web1"], runtime(bad))
    assert "web1: the image's uid 1000 exists on this host" in problems[0]
    assert "no such" in gate.check_existing([], ["gone"], runtime(bad))[0].lower()


def test_first_file_of_tar():
    import io
    import tarfile
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        data = b"root:x:0:0\n"
        info = tarfile.TarInfo("passwd")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/shadow"
        archive.addfile(link)
    assert _first_file_of_tar(buffer.getvalue()) == "root:x:0:0\n"
    assert _first_file_of_tar(b"not a tar") is None


# --- users on the command line ---------------------------------------------------

def test_as_resolves_a_local_account_on_the_host_and_docker_gets_ids(capsys):
    docker = FakeDocker(image_user="")  # root: would fall back if no user were given

    assert gate.run([], ["--as", "alice", "img"], runtime(docker)) == 42

    assert docker.calls[0][1] == [*DEFAULTS, "--user=4242:4343", "img"]
    assert docker.names().count("create") == 1  # a user was given: no fallback
    assert "[dockscreen] Resolving user alice to uid 4242, gid 4343" in capsys.readouterr().err


def test_as_with_an_account_the_host_does_not_have_is_refused_before_anything_is_created(capsys):
    docker = FakeDocker()
    assert gate.run([], ["--as", "www-data", "img"], runtime(docker)) == 1
    err = capsys.readouterr().err
    assert "user 'www-data' does not exist on this host; use --user with a numeric id" in err
    assert docker.calls == []


@pytest.mark.parametrize("flags", [["--user", "alice"], ["-u", "root"], ["--user=1000:staff"]])
def test_user_with_a_name_is_refused_before_anything_is_created(flags, capsys):
    docker = FakeDocker()
    assert gate.run([], [*flags, "img"], runtime(docker)) == 1
    err = capsys.readouterr().err
    assert "--user takes numeric ids as uid:gid" in err and "--as NAME runs as a local user" in err
    assert docker.calls == []


@pytest.mark.parametrize("kind, refused, pins_user, replaces_image_user", [
    (imagedecision.Kind.EXPLICIT, False, False, False),   # the command line's user runs as given
    (imagedecision.Kind.CONFIGURED, False, True, True),
    (imagedecision.Kind.OK, False, True, False),           # the image's own user, pinned as numbers
    (imagedecision.Kind.FALLBACK, False, True, True),
    (imagedecision.Kind.REFUSED, True, False, False),
    (imagedecision.Kind.FAILED, True, False, False),       # must not run either: nothing was checked
])
def test_assessment_predicates(kind, refused, pins_user, replaces_image_user):
    assessment = imagedecision.Assessment(kind, [])
    assert (assessment.refused, assessment.pins_user, assessment.replaces_image_user) == (
        refused, pins_user, replaces_image_user)


# --- image and project sections of the config file ---------------------------------

def test_an_image_section_changes_the_rules_for_that_image():
    settings = config.Config(images={"docker.io/library/img": config.Section(default_user=(65533, 65533))})
    docker = FakeDocker(image_user="", repo_digests=["img@sha256:abc"])
    assert gate.run([], ["img"], runtime(docker, settings)) == 42
    assert "--user=65533:65533" in docker.calls[3][1]


def test_a_project_section_applies_in_its_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    settings = config.Config(projects={str(tmp_path): config.Section(user=(65532, 65532))})
    docker = FakeDocker(image_user="app")
    assert gate.run([], ["img"], runtime(docker, settings)) == 42
    assert "--user=65532:65532" in docker.calls[3][1]  # configured: the image's own user is not used


def test_a_top_level_user_applies_to_every_image():
    docker = FakeDocker(image_user="web")  # would be refused: a local account
    assert gate.run([], ["img"], runtime(docker, config.Config(user=(65531, 65531)))) == 42
    assert "--user=65531:65531" in docker.calls[3][1]


