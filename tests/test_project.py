from dockscreen.model.origin import Origin
from dockscreen.model.project import Project, ProjectLocation


def project(**services):
    return Project({"name": "p", "services": services, "volumes": {"data": {}}}, ProjectLocation("/p"))


def test_a_service_is_its_projects_view_of_its_keys():
    web = project(web={"user": "1:1"}, db=None).service("web")

    assert (web.name, web.definition) == ("web", {"user": "1:1"})
    assert project(db=None).service("db").definition == {}  # compose leaves an empty service as null
    assert [s.name for s in project(web={}, db={}).services] == ["web", "db"]


def test_a_service_reaches_the_host_through_a_bind_mount_but_not_a_named_volume():
    named = {"volumes": [{"type": "volume", "source": "data", "target": "/d"}]}
    bound = {"volumes": [{"type": "bind", "source": "/p/x", "target": "/x"}]}

    assert not project(web=named).service("web").reaches_host
    assert project(web=bound).service("web").reaches_host


def test_its_values_are_the_projects_unless_origins_say_otherwise():
    found = project(web={}).with_origins({"web": {"user": Origin.IMAGE}})
    found = found.with_origins({"web": {"cap_drop": Origin.DOCKSCREEN}})  # added to, not replaced

    web = found.service("web")
    assert (web.origin_of("user"), web.origin_of("cap_drop"), web.origin_of("image")) == (
        Origin.IMAGE, Origin.DOCKSCREEN, Origin.PROJECT)
