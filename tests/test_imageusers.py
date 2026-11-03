from fakes import FakeImages, make_image_ctx, project_of

from dockscreen.compose import imageusers
from dockscreen.model.image import Inspected, Unseen

COMMAND = ["docker", "compose", "-f", "/gen/compose-0.yaml"]  # only the tail matters


def project(**services):
    return project_of({"name": "proj", "services": {
        name: {"image": f"{name}:1", **fields} for name, fields in services.items()}})


def test_every_started_image_is_got_but_only_those_asked_about_are_looked_at():
    images = FakeImages(users={"web:1": "app", "db:1": ""}, local={"web:1"})  # db:1 must be pulled
    ctx, recorder = make_image_ctx(images, active=("web", "db"))

    seen, failures = imageusers.find(COMMAND, project(web={}, db={"user": "7:7"}), {"web", "db"}, {"web"}, [],
                                     ctx)

    assert failures == [] and list(seen) == ["web"] and isinstance(seen["web"], Inspected)
    assert [cmd[len(COMMAND):] for cmd in recorder.children] == [["pull", "--", "db"]]


def test_nothing_is_looked_at_when_getting_an_image_fails():
    ctx, _ = make_image_ctx(FakeImages(users={"web:1": "app"}, local=()), active=("web",), codes={"pull": 1})

    seen, failures = imageusers.find(COMMAND, project(web={}), {"web"}, {"web"}, [], ctx)

    assert seen == {} and failures == ["docker compose pull web failed"]


def test_an_image_that_is_not_there_is_unseen():
    ctx, _ = make_image_ctx(FakeImages(), active=("web",))

    seen, _ = imageusers.find(COMMAND, project(web={"pull_policy": "never"}), {"web"}, {"web"}, [], ctx)

    assert isinstance(seen["web"], Unseen) and seen["web"].reason == "the image is not available locally"
