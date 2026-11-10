from fakes import marked

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project, ProjectLocation
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.substitutions import ProjectPatch, Substitution, SubstitutionGroup
from dockscreen.util import messages

PINNED = SubstitutionGroup("services {services}: pinned", "nothing to do")


def test_applied_to_definition_sets_each_key_on_a_copy():
    config = {"services": {"web": {"user": "0:0"}, "db": {}}}

    found = ProjectPatch.of([Substitution("web", "user", "1:1"), Substitution("db", "env", {"A": 1})])

    changed = found.applied_to_definition(config)

    assert changed == {"services": {"web": {"user": "1:1"}, "db": {"env": {"A": 1}}}}
    assert config == {"services": {"web": {"user": "0:0"}, "db": {}}}


def test_origins_are_those_of_the_last_substitution_of_a_key_that_names_one():
    found = ProjectPatch.of([
        Substitution("web", "user", "1:1", origin=Origin.IMAGE),
        Substitution("web", "user", "2:2", origin=Origin.CONFIG),
        Substitution("web", "user", "3:3"),  # respelled: still the config file's
        Substitution("db", "user", "4:4"),   # respelled only: the project's, so not listed
    ])

    assert found.origins() == {"web": {"user": Origin.CONFIG}}


def test_notices_give_a_line_each_then_one_per_group_naming_its_services_once():
    found = ProjectPatch.of([
        Substitution("web", "user", "1:1",
                     Notice("running as 1:1 instead of root", NoticeSeverity.WARNING, help="set user:"),
                     group=PINNED),
        Substitution("web", "pull_policy", "never", group=PINNED),
        Substitution("db", "user", "2:2", Notice("user 'db' resolved to 2:2")),
        Substitution("db", "pull_policy", "never", group=PINNED),
        Substitution("db", "environment", {"HOME": "/tmp"}),  # part of another change: not reported
    ])

    assert marked(found.notices()) == [
        f"{messages.WARN} service web: running as 1:1 instead of root",
        f"{messages.ROUTINE} service db: user 'db' resolved to 2:2",
        f"{messages.ROUTINE} services web, db: pinned",
    ]
    assert marked(found.group_notices()) == [
        f"{messages.ROUTINE} services web, db: pinned"]


def test_applied_to_makes_them_in_a_projects_definition_with_their_origins():
    found = Project({"services": {"web": {}}}, ProjectLocation("/p"))

    changed = ProjectPatch.of([Substitution("web", "user", "1:1", origin=Origin.CONFIG)]).applied_to(found)

    assert changed.definition == {"services": {"web": {"user": "1:1"}}}
    assert changed.service("web").origin_of("user") is Origin.CONFIG
    assert found.definition == {"services": {"web": {}}}


def test_a_patch_added_to_another_makes_its_changes_after_the_others():
    first = ProjectPatch.of([Substitution("web", "user", "1:1")])
    then = ProjectPatch.of([Substitution("web", "user", "2:2")])
    config = {"services": {"web": {}}}

    assert (first + then).applied_to_definition(config) == {"services": {"web": {"user": "2:2"}}}
    assert list(first + then) == [*first, *then] and len(ProjectPatch()) == 0
