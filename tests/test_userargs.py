import pytest
from fakes import id_facts, make_runtime, texts

from dockscreen.compose import runargs, userargs, userscreening
from dockscreen.compose.screener import Screener
from dockscreen.screen import policy

ME = (1000, 1001)  # what --as-me stands for
# the options of each command that take a value
VALUE_FLAGS = {**userargs.COMPOSE_VALUE_FLAGS, "docker exec": runargs.EXEC_VALUE_FLAGS}


def refusals(parsed):
    """Returns the texts of the policy's refusals of the users that parsed gives."""
    return texts(policy.Policy(id_facts()).check_user_options(parsed.users.given))



def parse(command, args):
    return userargs.parse(args, VALUE_FLAGS[command], ME, ACCOUNTS)


def screened(parsed):
    """The report of judging the users parsed gives, and parsed with --as and --as-me resolved."""
    return userscreening.screened(parsed, Screener(make_runtime()))


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
    assert (parsed.service, parsed.users.chosen, list(parsed.args)) == (service, user_given, args)


@pytest.mark.parametrize("args", [
    ["-u", "postgres", "web"], ["--user=1000", "web"], ["-iu", "root", "web"],
    ["--user", "1000:staff", "web"],
])
def test_users_must_be_numeric_uid_gid(args):
    [refusal] = refusals(parse("run", args))
    assert "--user takes numeric ids as uid:gid" in refusal


def test_exec_and_docker_exec_have_their_own_options():
    exec_args = ["--index", "2", "-u", "0:0", "web", "sh"]
    parsed = parse("exec", exec_args)
    assert (parsed.service, parsed.users.chosen) == ("web", True)
    parsed = parse("docker exec", ["--detach-keys", "x", "-it", "c", "sh"])
    assert (parsed.service, parsed.users.chosen) == ("c", False)
    assert refusals(parse("docker exec", ["--env-file", "e", "-u", "www-data", "c", "sh"]))


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
    report, parsed = screened(parse(subcommand, args))
    assert list(parsed.args) == rewritten
    assert parsed.users.chosen == ("--as" not in rewritten)
    resolving = ["Resolving user alice to uid 1001, gid 1002"]
    assert texts(report.notices) == ([] if "--as" in rewritten else resolving)


def test_as_with_an_unknown_name_is_refused():
    assert refusals(parse("exec", ["--as", "bob", "web", "sh"])) == [
        "user 'bob' does not exist on this host; use --user with a numeric id"]


def test_a_name_given_to_user_points_to_as():
    [refusal] = refusals(parse("exec", ["-u", "postgres", "web", "sh"]))
    assert "--as NAME runs as a local user" in refusal


def test_check_given_users_reports_what_the_policy_refuses():
    screener = Screener(make_runtime())

    assert screener.check_given_users(parse("exec", ["-u", "1000:1000", "web"]).users.given).passed
    refused = screener.check_given_users(parse("exec", ["-u", "postgres", "web"]).users.given)
    # the same refusals as the policy gives, as a report that stops the command
    assert not refused.passed
    assert texts(refused.findings) == refusals(parse("exec", ["-u", "postgres", "web"]))


@pytest.mark.parametrize("subcommand", ["run", "exec", "docker exec"])
def test_as_me_is_the_callers_ids(subcommand):
    _, parsed = screened(parse(subcommand, ["-it", "--as-me", "c", "sh"]))
    assert list(parsed.args) == ["-it", "--user=1000:1001", "c", "sh"] and parsed.users.chosen
