import pytest

from dockscreen import hostusers, userargs
from dockscreen.compose import composeargs
from dockscreen.run import runargs

ME = (1000, 1001)  # what --as-me stands for
# the options of each command that take a value
VALUE_FLAGS = {**composeargs.VALUE_FLAGS, "docker exec": runargs.EXEC_VALUE_FLAGS}


def parse(command, args):
    return userargs.parse(args, VALUE_FLAGS[command], ME, ACCOUNTS)


@pytest.mark.parametrize("args, service, user_given", [
    (["web"], "web", False),
    (["--rm", "-e", "A=1", "web", "sh", "-u", "x"], "web", False),  # after the service: the command's
    (["-u", "1000:1000", "web"], "web", True),
    (["--user=1000:1000", "web"], "web", True),
    (["--user", "1000:1000", "web"], "web", True),
    (["-iu1000:1000", "web"], "web", True),
    (["-Tu", "1000:1000", "web"], "web", True),
    (["--name", "x", "-v", "a:/b", "-w", "/w", "web"], "web", False),
    (["--", "web"], "web", False),
    ([], None, False),
])
def test_run_arguments(args, service, user_given):
    parsed = parse("run", args)
    assert (parsed.service, parsed.user_given, parsed.args) == (service, user_given, args)


@pytest.mark.parametrize("args", [
    ["-u", "postgres", "web"], ["--user=1000", "web"], ["-iu", "root", "web"],
    ["--user", "1000:staff", "web"],
])
def test_users_must_be_numeric_uid_gid(args):
    with pytest.raises(hostusers.UserError, match="--user takes numeric ids as uid:gid"):
        parse("run", args)


def test_exec_and_docker_exec_have_their_own_options():
    exec_args = ["--index", "2", "-u", "0:0", "web", "sh"]
    assert parse("exec", exec_args)[:2] == ("web", True)
    assert parse("docker exec", ["--detach-keys", "x", "-it", "c", "sh"])[:2] == ("c", False)
    with pytest.raises(hostusers.UserError):
        parse("docker exec", ["--env-file", "e", "-u", "www-data", "c", "sh"])


class Accounts:
    """A host whose only account is alice, 1001:1002."""

    def user(self, name):
        return (1001, 1002) if name == "alice" else None


ACCOUNTS = Accounts()


@pytest.mark.parametrize("subcommand, args, rewritten", [
    ("run", ["--rm", "--as", "alice", "web", "id"], ["--rm", "--user=1001:1002", "web", "id"]),
    ("run", ["--as=alice", "--", "web"], ["--user=1001:1002", "--", "web"]),
    ("exec", ["-T", "--as", "alice", "web", "sh"], ["-T", "--user=1001:1002", "web", "sh"]),
    ("docker exec", ["-it", "--as=alice", "c", "sh"], ["-it", "--user=1001:1002", "c", "sh"]),
    # after the service, --as belongs to the command
    ("run", ["web", "tool", "--as", "bob"], ["web", "tool", "--as", "bob"]),
])
def test_as_is_resolved_on_this_host_and_replaced_by_numeric_ids(subcommand, args, rewritten):
    parsed = parse(subcommand, args)
    assert parsed.args == rewritten
    assert parsed.user_given == ("--as" not in rewritten)
    assert parsed.notices == ([] if "--as" in rewritten else ["Resolving user alice to uid 1001, gid 1002"])


def test_as_with_an_unknown_name_is_an_error():
    with pytest.raises(hostusers.UnknownUser):
        parse("exec", ["--as", "bob", "web", "sh"])


def test_a_name_given_to_user_points_to_as():
    with pytest.raises(hostusers.UserError, match="--as NAME runs as a local user"):
        parse("exec", ["-u", "postgres", "web", "sh"])


@pytest.mark.parametrize("subcommand", ["run", "exec", "docker exec"])
def test_as_me_is_the_callers_ids(subcommand):
    parsed = parse(subcommand, ["-it", "--as-me", "c", "sh"])
    assert parsed.args == ["-it", "--user=1000:1001", "c", "sh"] and parsed.user_given
