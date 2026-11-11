from fakes import FakeImages, make_screener, project_of, texts

from dockscreen.model.image import Inspected, Unseen
from dockscreen.screen import imageusers

COMMAND = ["docker", "compose", "-f", "/gen/compose-0.yaml"]  # only the tail matters


def project(**services):
    return project_of({"name": "proj", "services": {
        name: {"image": f"{name}:1", **fields} for name, fields in services.items()}})


def test_every_started_image_is_got_but_only_those_asked_about_are_looked_at():
    images = FakeImages(users={"web:1": "app", "db:1": ""}, local={"web:1"})  # db:1 must be pulled
    screener, recorder = make_screener(images, active=("web", "db"))

    seen, failures = imageusers.find(COMMAND, project(web={}, db={"user": "7:7"}), {"web", "db"}, {"web"}, [],
                                     screener)

    assert failures == [] and list(seen) == ["web"] and isinstance(seen["web"], Inspected)
    assert [cmd[len(COMMAND):] for cmd in recorder.children] == [["pull", "--", "db"]]


def test_nothing_is_looked_at_when_getting_an_image_fails():
    images = FakeImages(users={"web:1": "app"}, local=())
    screener, _ = make_screener(images, active=("web",), codes={"pull": 1})

    seen, failures = imageusers.find(COMMAND, project(web={}), {"web"}, {"web"}, [], screener)

    assert seen == {} and texts(failures) == ["docker compose pull web failed"]


def test_an_image_that_is_not_there_is_unseen():
    screener, _ = make_screener(FakeImages(), active=("web",))

    seen, _ = imageusers.find(COMMAND, project(web={"pull_policy": "never"}), {"web"}, {"web"}, [], screener)

    assert isinstance(seen["web"], Unseen) and seen["web"].reason == "the image is not available locally"
