import fakes
import pytest

from dockscreen.cli import runargs
from dockscreen.compose import userscreening
from dockscreen.compose.screener import Screener
from dockscreen.screen import policy
from dockscreen.screen.rules.userrules import UserOption

ME = (4242, 4343)


def refusals(parsed):
    """Returns the texts of the policy's refusals of the users that parsed gives."""
    return fakes.texts(policy.Policy(fakes.id_facts()).check_user_options(parsed.users.given))


def parse(*args):
    return runargs.parse(list(args), ME, fakes.Accounts())


def screened(parsed):
    """The report of judging the users parsed gives, and parsed with --as and --as-me resolved."""
    return userscreening.screened(parsed, Screener(fakes.make_runtime()))


def test_plain_command():
    parsed = parse("-it", "--rm", "alpine", "sh", "-c", "echo hi")
    assert list(parsed.create_args) == ["-it", "--rm", "alpine", "sh", "-c", "echo hi"]
    assert (parsed.image, list(parsed.command), parsed.detach) == ("alpine", ["sh", "-c", "echo hi"], False)


def test_values_are_not_mistaken_for_the_image():
    parsed = parse("--name", "web", "-p", "80:80", "-v", "/a:/b", "-e", "A=1", "--user=1:1", "-w", "/x",
                   "img", "cmd")
    assert parsed.image == "img" and list(parsed.command) == ["cmd"]
    assert list(parsed.create_args)[-2:] == ["img", "cmd"]
    assert list(parsed.create_args)[:2] == ["--name", "web"]


def test_attached_short_values():
    parsed = parse("-p80:80", "-eA=1", "-v/a:/b", "img")
    assert parsed.image == "img"
    assert list(parsed.create_args) == ["-p80:80", "-eA=1", "-v/a:/b", "img"]


@pytest.mark.parametrize("flags, detach, kept", [
    (["-d"], True, []),
    (["--detach"], True, []),
    (["--detach=false"], False, []),
    (["-dit"], True, ["-it"]),
    (["-itd"], True, ["-it"]),
    (["--sig-proxy=false"], False, []),
    (["--detach-keys", "ctrl-x"], False, []),
    (["--detach-keys=ctrl-x"], False, []),
    (["-a", "stdout"], False, []),
    (["--attach=stdin"], False, []),
    (["-dp", "80:80"], True, ["-p", "80:80"]),
])
def test_flags_that_create_lacks_are_dropped(flags, detach, kept):
    parsed = parse(*flags, "img")
    assert list(parsed.create_args) == [*kept, "img"]
    assert parsed.detach is detach


def test_detach_keys_are_remembered():
    assert parse("--detach-keys", "ctrl-x", "img").detach_keys == "ctrl-x"
    assert parse("--detach-keys=ctrl-y", "img").detach_keys == "ctrl-y"


def test_flags_after_the_image_belong_to_the_command():
    parsed = parse("img", "ls", "-d", "--detach", "-a")
    assert list(parsed.create_args) == ["img", "ls", "-d", "--detach", "-a"]
    assert not parsed.detach


def test_double_dash_ends_the_options():
    parsed = parse("--rm", "--", "img", "-d")
    assert list(parsed.create_args) == ["--rm", "--", "img", "-d"]
    assert (parsed.image, list(parsed.command)) == ("img", ["-d"])


@pytest.mark.parametrize("args", [[], ["--rm"], ["-it"], ["--name"], ["-p"], ["-a"]])
def test_incomplete_command_lines_are_errors(args):
    with pytest.raises(runargs.ParseError):
        runargs.parse(args, ME, fakes.Accounts())


def test_as_me_means_the_callers_ids_and_resolves_nothing():
    parsed = runargs.parse(["--as-me", "img"], ME, accounts=None)  # looking anything up would fail
    assert list(parsed.create_args) == [UserOption("--as-me", "", ME), "img"]  # reading changes nothing
    report, parsed = screened(parsed)
    assert list(parsed.create_args) == ["--user=4242:4343", "img"]
    assert parsed.users.chosen and report.passed and report.notices == ()


def test_current_user_is_no_longer_a_flag_of_ours():
    parsed = parse("--current-user", "img")
    assert list(parsed.create_args) == ["--current-user", "img"]  # docker will reject it
    assert not parsed.users.chosen


@pytest.mark.parametrize("flags", [["--as", "alice"], ["--as=alice"]])
def test_as_resolves_a_local_account_on_the_host(flags):
    parsed = runargs.parse([*flags, "img"], ME, fakes.Accounts())
    assert list(parsed.create_args) == [UserOption("--as", "alice", ME), "img"]
    report, parsed = screened(parsed)
    assert list(parsed.create_args) == ["--user=4242:4343", "img"]
    assert fakes.texts(report.notices) == ["Resolving user alice to uid 4242, gid 4343"]
    assert parsed.users.chosen


def test_an_as_that_was_not_resolved_cannot_reach_docker():
    parsed = runargs.parse(["--as", "ghost", "img"], ME, fakes.Accounts())
    report, resolved = screened(parsed)
    assert not report.passed and resolved is None
    with pytest.raises(KeyError):
        parsed.resolved({})  # nothing to stand for


def test_as_with_an_unknown_account_or_an_id_is_refused():
    assert refusals(runargs.parse(["--as", "ghost", "img"], ME, fakes.Accounts())) == [
        "user 'ghost' does not exist on this host; use --user with a numeric id"]
    assert refusals(runargs.parse(["--as", "1000", "img"], ME, fakes.Accounts())) == [
        "--as takes the name of a local user, not '1000'; use --user for ids"]
    with pytest.raises(runargs.ParseError):
        runargs.parse(["--as"], ME, fakes.Accounts())


@pytest.mark.parametrize("flags, user", [
    (["--user", "1000:1000"], "1000:1000"),
    (["--user=0:0"], "0:0"),
    (["-u", "7:8"], "7:8"),
    (["-u7:8"], "7:8"),
    (["-itu", "7:8"], "7:8"),
])
def test_user_ids_are_passed_on_as_typed_and_recorded(flags, user):
    report, parsed = screened(parse(*flags, "img"))
    assert list(parsed.create_args) == [*flags, "img"]
    assert parsed.users.given == [UserOption("--user", user)]
    assert parsed.users.chosen and report.notices == ()


@pytest.mark.parametrize("flags", [
    ["--user", "alice"], ["--user=nobody"], ["-u", "root"], ["-ualice"], ["-itu", "alice"],
    ["--user", "1000:staff"], ["--user", "me"],
    ["--user", "1000"], ["--user=0"], ["-u", "7"],  # a uid alone leaves the group to the image
])
def test_user_names_are_refused_with_a_pointer_to_as(flags):
    [refusal] = refusals(parse(*flags, "img"))
    assert "--user takes numeric ids as uid:gid" in refusal


def test_a_user_flag_in_a_cluster_stays_in_it():
    assert list(parse("-itu", "7:8", "img").create_args) == ["-itu", "7:8", "img"]


def test_user_flags_after_the_image_belong_to_the_command():
    parsed = parse("img", "id", "-u", "--as-me", "--as", "alice")
    assert not parsed.users.chosen
    assert list(parsed.create_args) == ["img", "id", "-u", "--as-me", "--as", "alice"]


def test_no_user_flag_means_not_given():
    assert not parse("-it", "img").users.chosen
