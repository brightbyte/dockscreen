import pytest

from dockscreen.model import mounts
from dockscreen.model.mounts import Mount

BIND = {"volumes": [{"type": "bind", "source": "/p/data", "target": "/data"}]}


@pytest.mark.parametrize("fields, reaches", [
    ({}, False),
    (BIND, True),
    ({"volumes": [{"type": "volume", "source": "d", "target": "/d"}, {"type": "tmpfs", "target": "/t"}]},
     False),
    ({"secrets": [{"source": "s"}]}, True),
    ({"configs": [{"source": "c"}]}, True),
    ({"volumes_from": ["other"]}, True),
    ({"devices": ["/dev/dri:/dev/dri"]}, True),
    ({"volumes": ["/short/syntax:/not-normalized"]}, False),  # config output is always the long form
])
def test_which_services_reach_host_files(fields, reaches):
    assert mounts.service_reaches_host(fields) is reaches


@pytest.mark.parametrize("volumes, reaches", [
    ({}, False),
    ({"d": {"name": "proj_d"}}, False),
    ({"d": {"name": "proj_d", "driver_opts": {"type": "tmpfs", "device": "tmpfs", "o": "size=1m"}}}, False),
    ({"d": {"name": "proj_d", "driver_opts": {"type": "none", "o": "bind", "device": "/p/data"}}}, True),
    ({"d": {"name": "proj_d", "driver_opts": {"type": "tmpfs", "o": "bind", "device": "/etc"}}}, True),
])
def test_a_named_volume_set_up_as_a_bind_mount_reaches_host_files(volumes, reaches):
    web = {"volumes": [{"type": "volume", "source": "d", "target": "/h"}]}
    assert mounts.service_reaches_host(web, volumes) is reaches


@pytest.mark.parametrize("extra", [
    {"Mounts": [{"Type": "bind", "Source": "/p", "Destination": "/p"}]},
    {"HostConfig": {"Binds": ["/p:/p:ro"]}},
    {"HostConfig": {"Mounts": [{"Type": "bind"}]}},
    {"HostConfig": {"Devices": [{"PathOnHost": "/dev/dri"}]}},
    {"HostConfig": {"VolumesFrom": ["other"]}},
])
def test_which_containers_reach_host_files(extra):
    assert mounts.container_reaches_host({"Config": {}, **extra})


@pytest.mark.parametrize("extra", [
    {},
    {"Mounts": [{"Type": "volume", "Name": "data"}, {"Type": "tmpfs"}]},
    {"HostConfig": {"Binds": ["data:/var/lib/data"], "Devices": [], "VolumesFrom": None}},
])
def test_named_volumes_and_tmpfs_of_a_container_are_not_host_mounts(extra):
    assert not mounts.container_reaches_host({"Config": {}, **extra})


def test_a_containers_mounts_from_v_and_mount_are_listed_once_each():
    info = {"HostConfig": {"Binds": ["/etc:/etc:ro", "/work/src:/src", "data:/data"],
                           "Mounts": [{"Type": "bind", "Source": "/srv", "Target": "/srv"}]},
            "Mounts": [{"Type": "bind", "Source": "/etc", "Destination": "/etc"},
                       {"Type": "volume", "Source": "/var/lib/docker/volumes/data/_data",
                        "Destination": "/data"}]}

    assert mounts.container_mounts(info) == [
        Mount("bind", "/etc", "/etc"), Mount("bind", "/work/src", "/src"), Mount("bind", "/srv", "/srv"),
        Mount("volume", "/var/lib/docker/volumes/data/_data", "/data")]
