from dockscreen.model.container import Container
from dockscreen.model.origin import Origin

HARDENED = {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"]}


def container(user="", **host):
    return Container({"Config": {"User": user}, "HostConfig": {**HARDENED, **host}}, "/work")


def test_as_service_asks_for_what_the_container_has_in_compose_keys():
    found = container(NetworkMode="default", IpcMode="private", Runtime="runc", Privileged=False)

    assert found.as_service(with_user=False) == {
        "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "runtime": "runc",
        "ipc": "private", "network_mode": "default"}  # Privileged=False asks for nothing


def test_as_service_names_other_containers_volumes_and_lists_the_mounts():
    found = container(VolumesFrom=["db"], Devices=[{"PathOnHost": "/dev/kvm"}], Binds=["/etc:/etc:ro"])

    service = found.as_service(with_user=False)

    assert service["volumes_from"] == ["container:db"]
    assert service["devices"] == [{"PathOnHost": "/dev/kvm"}]
    assert service["volumes"] == [{"type": "bind", "source": "/etc", "target": "/etc"}]
    assert found.reaches_host


def test_as_service_has_the_user_only_when_asked_to():
    assert "user" not in container(user="0:0").as_service(with_user=False)
    assert container(user="0:0").as_service(with_user=True)["user"] == "0:0"
    assert container().as_service(with_user=True)["user"] == ""  # the image's, which run decides


def test_its_definition_has_its_user_unless_that_comes_from_its_image():
    assert container(user="0:0").definition["user"] == "0:0"  # the command line's, by default
    from_image = container(user="0:0").with_user_origin(Origin.IMAGE)

    assert "user" not in from_image.definition
    assert (from_image.origin_of("user"), from_image.origin_of("cap_drop")) == (Origin.IMAGE,
                                                                               Origin.COMMAND_LINE)
