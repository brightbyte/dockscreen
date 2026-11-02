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
