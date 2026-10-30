import pytest
from fakes import FakeDocker, FakeImages, make_image_ctx, runtime

from dockscreen.compose import compose_cli, composerun, screen
from dockscreen.dockerclient import Docker, DockerError


class Ps:
    """subprocess.run for `docker ps`: its output, and the command."""

    def __init__(self, out="", code=0, err=""):
        self.out, self.code, self.err = out, code, err
        self.commands = []

    def __call__(self, cmd, **kwargs):
        self.commands.append(cmd)
        return type("Result", (), {"returncode": self.code, "stdout": self.out, "stderr": self.err})()


def test_the_containers_of_a_project_are_found_by_its_label_whether_running_or_not():
    ps = Ps("/a\n\n/b\n")

    assert Docker("docker", run=ps).project_directories("proj") == ["/a", "", "/b"]
    assert ps.commands == [["docker", "ps", "--all", "--filter", "label=com.docker.compose.project=proj",
                            "--format", '{{.Label "com.docker.compose.project.working_dir"}}']]


def test_docker_failing_to_say_is_an_error():
    with pytest.raises(DockerError, match="daemon down"):
        Docker("docker", run=Ps(code=1, err="daemon down")).project_directories("proj")


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
        def project_directories(self, name):
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


def project(tmp_path, **config):
    return {"name": "proj", "services": {"web": {"image": "x:1", "user": "65534:65534"}}, **config}


def test_up_refuses_a_name_that_other_containers_have_and_runs_nothing(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(screen, "inspect", lambda global_args, rt: (project(tmp_path), str(tmp_path)))
    images = FakeImages(users={"x:1": "app"})
    images.project_dirs = ["/victim"]
    image_ctx, recorder = make_image_ctx(images)

    assert composerun.run(["up"], 0, runtime(), image_ctx) == 1

    assert "project name 'proj' is used by containers made from '/victim'" in capsys.readouterr().err
    assert recorder.children == []


@pytest.mark.parametrize("argv, idx", [(["up"], 0), (["-p", "proj", "up"], 2)])
def test_up_runs_in_the_directory_that_made_the_containers_or_when_p_names_the_project(
        monkeypatch, tmp_path, argv, idx):
    monkeypatch.setattr(screen, "inspect", lambda global_args, rt: (project(tmp_path), str(tmp_path)))
    images = FakeImages(users={"x:1": "app"})
    images.project_dirs = [str(tmp_path)] if argv == ["up"] else ["/victim"]
    image_ctx, recorder = make_image_ctx(images)

    composerun.run(argv, idx, runtime(), image_ctx)

    assert recorder.children  # compose ran


@pytest.mark.parametrize("sub", ["down", "rm", "stop", "kill", "restart", "start", "pause", "unpause"])
def test_commands_that_remove_or_stop_are_refused_for_a_name_that_is_not_the_projects(
        monkeypatch, tmp_path, capsys, sub):
    monkeypatch.setattr(screen, "inspect", lambda global_args, rt: (project(tmp_path), str(tmp_path)))
    images = FakeImages()
    images.project_dirs = ["/victim"]
    forwarded = []
    monkeypatch.setattr(compose_cli, "forward", lambda argv, rt: forwarded.append(argv))

    code = compose_cli.main([sub, "-v"] if sub == "down" else [sub], runtime(docker=images))

    assert code == 1 and forwarded == []
    assert "project name 'proj' is used by containers made from '/victim'" in capsys.readouterr().err


def test_down_goes_on_for_the_projects_own_name_with_p_and_for_a_project_that_cannot_be_read(
        monkeypatch, tmp_path):
    images = FakeImages()
    images.project_dirs = ["/victim"]
    forwarded = []
    monkeypatch.setattr(compose_cli, "forward", lambda argv, rt: forwarded.append(argv))
    monkeypatch.setattr(screen, "inspect", lambda global_args, rt: (project(tmp_path), str(tmp_path)))

    compose_cli.main(["-p", "mine", "down"], runtime(docker=images))
    images.project_dirs = [str(tmp_path)]
    compose_cli.main(["down"], runtime(docker=images))

    def unreadable(global_args, rt):
        raise screen.InspectError("no compose file")

    monkeypatch.setattr(screen, "inspect", unreadable)
    images.project_dirs = ["/victim"]
    compose_cli.main(["down"], runtime(docker=images))

    assert forwarded == [["-p", "mine", "down"], ["down"], ["down"]]
