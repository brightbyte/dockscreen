from types import MappingProxyType

import pytest

from dockscreen.model.settings import Config, ConfigSection, SectionMatch
from dockscreen.policy import sections


def test_the_settings_a_section_sets_count_as_configured_where_it_applies():
    settings = Config(projects=MappingProxyType({"/p": ConfigSection(default_user=(5, 5))}))
    assert sections.effective_settings(settings).configured_keys == frozenset()
    assert sections.effective_settings(settings, None, "/p/sub").configured_keys == {"default_user"}


def test_effective_settings_apply_the_image_then_the_projects_outermost_first(tmp_path):
    shop = tmp_path / "src" / "shop"
    (shop / "web").mkdir(parents=True)
    settings = Config(
        user=(1, 1), mount_dirs=("/top",), security_opts=("a",),
        images={"docker.io/library/mariadb": ConfigSection(user=(999, 999), mount_dirs=("/img",))},
        projects={str(tmp_path / "src"): ConfigSection(user=(2, 2), mount_dirs=("/src",)),
                  str(shop): ConfigSection(security_opts=("b", "a"), default_user=(3, 3))})

    found = sections.effective_settings(settings, "docker.io/library/mariadb", str(shop / "web"))
    assert found.user == (2, 2)                       # replaced: the outer project's comes after the image's
    assert found.default_user == (3, 3)
    assert found.mount_dirs == ("/top", "/img", "/src")  # added to, in order, each once
    assert found.security_opts == ("a", "b")
    assert found.images == {} and found.projects == {}

    without_sections = Config(user=(1, 1), mount_dirs=("/top",), security_opts=("a",))
    assert sections.effective_settings(settings) == without_sections
    assert sections.effective_settings(settings, None, "/elsewhere").user == (1, 1)
    assert sections.effective_settings(settings, "docker.io/library/redis",
                                       str(tmp_path)).mount_dirs == ("/top",)


IMAGE_SECTION = Config(images={"docker.io/library/mariadb": ConfigSection(user=(999, 999))})


def test_an_image_pulled_from_the_sections_repository_gets_the_section():
    match = sections.section_for(IMAGE_SECTION, "mariadb:11", ["mariadb@sha256:abc"], is_built=False)
    assert match == SectionMatch("docker.io/library/mariadb", None)
    # the digest may be recorded under any spelling of the repository
    match = sections.section_for(IMAGE_SECTION, "docker.io/library/mariadb",
                                 ["docker.io/library/mariadb@sha256:a"], is_built=False)
    assert match.repository == "docker.io/library/mariadb"


@pytest.mark.parametrize("reference, digests, built, problem", [
    ("mariadb:11", [], False, "this image was not pulled from there"),
    ("mariadb:11", ["evil.example/mariadb@sha256:abc"], False, "this image was not pulled from there"),
    ("mariadb:11", ["mariadb@sha256:abc"], True, "the service builds its image"),
])
def test_an_image_that_only_has_the_name_does_not_get_the_section(reference, digests, built, problem):
    match = sections.section_for(IMAGE_SECTION, reference, digests, built)
    assert match.repository is None and match.problem.endswith(problem)
    # before the image is there, the name alone points to the section, unless the service builds it
    expected = None if built else "docker.io/library/mariadb"
    assert sections.repository_for_name(IMAGE_SECTION, reference, built) == expected


@pytest.mark.parametrize("reference", ["redis", "evil.example/mariadb", "someone/mariadb", "sha256:abc"])
def test_other_repositories_have_no_section(reference):
    match = sections.section_for(IMAGE_SECTION, reference, ["x@sha256:a"], is_built=False)
    assert match == SectionMatch(None, None)
