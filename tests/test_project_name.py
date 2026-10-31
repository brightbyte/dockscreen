import pytest
from fakes import FakeImages, compose_project

from dockscreen.compose import compose_cli, composerun, screen
from dockscreen.dockerclient import DockerError


def test_the_containers_of_a_project_are_found_by_its_label_and_say_where_they_were_made():
    asked = []

    class Labels:
        def label_values(self, label, value, wanted):
            asked.append((label, value, wanted))
            return []

    screen.name_conflicts("proj", "/p", Labels())
    assert asked == [("com.docker.compose.project", "proj", "com.docker.compose.project.working_dir")]


def conflicts(found, directory="/p"):
    docker = FakeImages()
    docker.project_dirs = found
    return screen.name_conflicts("proj", directory, docker)


def test_a_name_is_free_when_no_container_or_only_ones_of_this_directory_have_it(tmp_path):
    assert conflicts([]) == []
    assert conflicts([str(tmp_path), str(tmp_path / ".")], str(tmp_path)) == []


def test_a_name_used_from_another_directory_is_refused_with_the_way_out(tmp_path):
    problems = conflicts([str(tmp_path / "victim"), str(tmp_path)], str(tmp_path))

    assert len(problems) == 1
    assert f"project name 'proj' is used by containers made from '{tmp_path / 'victim'}'" in problems[0]
    assert "-p NAME" in problems[0].help


def test_containers_without_a_directory_label_count_as_another_project():
    assert "an unknown directory" in conflicts([""])[0]


def test_not_being_able_to_ask_is_a_refusal():
    class Broken:
        def label_values(self, label, value, wanted):
            raise DockerError("daemon down")

    assert screen.name_conflicts("proj", "/p", Broken()) == [
        "cannot tell whether another project is called 'proj': daemon down"]


@pytest.mark.parametrize("args, env, chosen", [
    ([], {}, False),
    (["-p", "x"], {}, True),
    (["--project-name=x"], {}, True),
    ([], {"COMPOSE_PROJECT_NAME": "x"}, True),
    ([], {"COMPOSE_PROJECT_NAME": ""}, False),
    (["-f", "-p"], {}, False),
])
def test_the_person_chooses_the_name_with_p_or_the_environment(args, env, chosen):
    assert screen.names_project(args, env) is chosen


PROJECT = {"name": "proj", "services": {"web": {"image": "x:1", "user": "65534:65534"}}}


def test_up_refuses_a_name_that_other_containers_have_and_runs_nothing(tmp_path, capsys):
    images = FakeImages(users={"x:1": "app"})
    images.project_dirs = ["/victim"]
    runtime, recorder = compose_project(tmp_path, PROJECT, images)

    assert composerun.run(["up"], 0, runtime) == 1

    assert "project name 'proj' is used by containers made from '/victim'" in capsys.readouterr().err
    assert recorder.children == []


@pytest.mark.parametrize("argv, idx", [(["up"], 0), (["-p", "proj", "up"], 2)])
def test_up_runs_in_the_directory_that_made_the_containers_or_when_p_names_the_project(tmp_path, argv, idx):
    images = FakeImages(users={"x:1": "app"})
    images.project_dirs = [str(tmp_path)] if argv == ["up"] else ["/victim"]
    runtime, recorder = compose_project(tmp_path, PROJECT, images)

    composerun.run(argv, idx, runtime)

    assert recorder.children  # compose ran


@pytest.mark.parametrize("sub", ["down", "rm", "stop", "kill", "restart", "start", "pause", "unpause"])
def test_commands_that_remove_or_stop_are_refused_for_a_name_that_is_not_the_projects(tmp_path, capsys, sub):
    images = FakeImages()
    images.project_dirs = ["/victim"]
    runtime, _ = compose_project(tmp_path, PROJECT, images)

    code = compose_cli.main([sub, "-v"] if sub == "down" else [sub], runtime)

    assert code == 1 and images.forwarded == []
    assert "project name 'proj' is used by containers made from '/victim'" in capsys.readouterr().err


def test_down_goes_on_for_the_projects_own_name_with_p_and_for_a_project_that_cannot_be_read(tmp_path):
    images = FakeImages()
    images.project_dirs = ["/victim"]
    runtime, _ = compose_project(tmp_path, PROJECT, images)

    compose_cli.main(["-p", "mine", "down"], runtime)
    images.project_dirs = [str(tmp_path)]
    compose_cli.main(["down"], runtime)

    (tmp_path / "compose.yaml").write_text("services: [")  # compose cannot read it
    images.project_dirs = ["/victim"]
    compose_cli.main(["down"], runtime)

    assert images.forwarded == [["-p", "mine", "down"], ["down"], ["down"]]
