from dockscreen.model.origin import Origin
from dockscreen.model.project import Location, Project
from dockscreen.screen import substitutions
from dockscreen.screen.substitutions import Group, Substitution
from dockscreen.util import messages

PINNED = Group("services {services}: pinned", "nothing to do")


def test_apply_sets_each_key_on_a_copy():
    config = {"services": {"web": {"user": "0:0"}, "db": {}}}

    found = [Substitution("web", "user", "1:1"), Substitution("db", "env", {"A": 1})]

    changed = substitutions.apply(config, found)

    assert changed == {"services": {"web": {"user": "1:1"}, "db": {"env": {"A": 1}}}}
    assert config == {"services": {"web": {"user": "0:0"}, "db": {}}}


def test_origins_are_those_of_the_last_substitution_of_a_key_that_names_one():
    found = [
        Substitution("web", "user", "1:1", origin=Origin.IMAGE),
        Substitution("web", "user", "2:2", origin=Origin.CONFIG),
        Substitution("web", "user", "3:3"),  # respelled: still the config file's
        Substitution("db", "user", "4:4"),   # respelled only: the project's, so not listed
    ]

    assert substitutions.origins(found) == {"web": {"user": Origin.CONFIG}}


def test_describe_gives_a_line_each_then_one_per_group_naming_its_services_once():
    found = [
        Substitution("web", "user", "1:1", "running as 1:1 instead of root", notable=True, help="set user:",
                     group=PINNED),
        Substitution("web", "pull_policy", "never", group=PINNED),
        Substitution("db", "user", "2:2", "user 'db' resolved to 2:2"),
        Substitution("db", "pull_policy", "never", group=PINNED),
        Substitution("db", "environment", {"HOME": "/tmp"}),  # part of another change: not reported
    ]

    assert substitutions.describe(found) == [
        messages.notable_change("service web: running as 1:1 instead of root", "set user:"),
        messages.routine_change("service db: user 'db' resolved to 2:2"),
        messages.routine_change("services web, db: pinned", "nothing to do"),
    ]
    assert substitutions.grouped(found) == [
        messages.routine_change("services web, db: pinned", "nothing to do")]


def test_applied_makes_them_in_a_projects_definition_with_their_origins():
    found = Project({"services": {"web": {}}}, Location("/p"))

    changed = substitutions.applied(found, [Substitution("web", "user", "1:1", origin=Origin.CONFIG)])

    assert changed.definition == {"services": {"web": {"user": "1:1"}}}
    assert changed.service("web").origin_of("user") is Origin.CONFIG
    assert found.definition == {"services": {"web": {}}}
