from fakes import make_runtime, project_of

from dockscreen.compose import runoptions, userargs
from dockscreen.model.origin import Origin

ME = (1000, 1001)


def run(service, *args, cwd="/work", home="/home/me"):
    """The service web, with service as its keys, as `compose run args web` runs it."""
    parsed = userargs.parse_compose("run", [*args, "web"], ME, None)
    project = project_of({"services": {"web": service}})
    found = runoptions.substitutions(parsed, project.service("web"), make_runtime(cwd=cwd, home=home))
    return found.applied_to(project).service("web")


def test_options_that_set_no_checked_key_change_nothing():
    web = run({"user": "1:1"}, "--rm", "-e", "A=1", "-w", "/w", "--entrypoint", "sh", "-l", "a=b")
    assert web.definition == {"user": "1:1"}


def test_the_last_user_replaces_the_services_and_comes_from_the_command_line():
    web = run({"user": "1:1"}, "-u", "2:2", "--user=0:0")
    assert (web.definition["user"], web.origin_of("user")) == ("0:0", Origin.COMMAND_LINE)


def test_volumes_are_added_in_compose_long_syntax():
    web = run({"volumes": [{"type": "volume", "source": "data", "target": "/d"}]},
              "-v", "/etc:/e:ro", "--volume=cache:/c", "-v", "~/.ssh:/s", "-v", "/anon")

    assert web.definition["volumes"] == [
        {"type": "volume", "source": "data", "target": "/d"},
        {"type": "bind", "source": "/etc", "target": "/e", "read_only": True},
        {"type": "volume", "source": "cache", "target": "/c"},
        {"type": "bind", "source": "/home/me/.ssh", "target": "/s"},  # judged as compose could mean it
        {"type": "volume", "target": "/anon"}]
    assert web.origin_of("volumes") is Origin.COMMAND_LINE
    assert run({}, "-v", "a:b:c:d").definition["volumes"] == [{"source": "a:b:c:d"}]  # no type: refused


def test_capabilities_are_added_and_taken_out_of_the_other_list_as_compose_does():
    web = run({"cap_add": ["NET_RAW"], "cap_drop": ["ALL", "CHOWN"]}, "--cap-add", "CHOWN",
              "--cap-drop", "NET_RAW")

    assert web.definition["cap_add"] == ["CHOWN"]
    assert web.definition["cap_drop"] == ["ALL", "NET_RAW"]
    assert run({"cap_drop": ["ALL"]}, "--cap-add", "ALL").definition["cap_drop"] == []


def test_an_env_file_from_the_command_line_is_read_from_the_current_directory():
    web = run({"env_file": "a.env"}, "--env-from-file", "b.env")
    assert web.definition["env_file"] == ["a.env", "/work/b.env"]
