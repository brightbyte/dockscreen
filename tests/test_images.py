import pytest

from dockscreen import images


@pytest.mark.parametrize("reference, split", [
    ("mariadb", ("docker.io/library/mariadb", "", "")),
    ("mariadb:11", ("docker.io/library/mariadb", "11", "")),
    ("library/mariadb", ("docker.io/library/mariadb", "", "")),
    ("docker.io/mariadb", ("docker.io/library/mariadb", "", "")),
    ("index.docker.io/library/mariadb:11", ("docker.io/library/mariadb", "11", "")),
    ("someone/mariadb", ("docker.io/someone/mariadb", "", "")),
    ("ghcr.io/acme/app:1.2", ("ghcr.io/acme/app", "1.2", "")),
    ("localhost/app", ("localhost/app", "", "")),
    ("registry:5000/team/app:tag", ("registry:5000/team/app", "tag", "")),
    ("mariadb@sha256:abc", ("docker.io/library/mariadb", "", "sha256:abc")),
    ("mariadb:11@sha256:abc", ("docker.io/library/mariadb", "11", "sha256:abc")),
])
def test_references_are_normalised_as_docker_does(reference, split):
    assert images.split_reference(reference) == split


@pytest.mark.parametrize("reference", ["", "Mariadb", "a b", "x/", "-x"])
def test_what_is_not_a_reference_is_an_error(reference):
    with pytest.raises(ValueError):
        images.split_reference(reference)
    assert images.repository(reference) is None


@pytest.mark.parametrize("repository, shown", [
    ("docker.io/library/mariadb", "mariadb"), ("docker.io/bitnami/redis", "bitnami/redis"),
    ("ghcr.io/acme/app", "ghcr.io/acme/app"),
])
def test_shown(repository, shown):
    assert images._shown(repository) == shown
