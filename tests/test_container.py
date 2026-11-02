from dockscreen.model.container import Container

HARDENED = {"CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges:true"]}


def container(user="", **host):
    return Container({"Config": {"User": user}, "HostConfig": {**HARDENED, **host}})


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
