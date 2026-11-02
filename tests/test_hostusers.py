
from dockscreen.host import hostusers
from dockscreen.host.hostusers import HostAccounts


def test_host_accounts_use_nss():
    accounts = HostAccounts()
    assert accounts.user("root") == (0, 0) and accounts.group("root") == 0
    assert accounts.user_name(0) == "root" and accounts.group_name(0) == "root"
    assert accounts.user("no-such-user-here") is None and accounts.group("no-such-group-here") is None
    assert accounts.user_name(2**31 - 3) is None and accounts.group_name(2**31 - 3) is None


def test_missing_subordinate_files_mean_no_ranges(tmp_path):
    subordinate = hostusers.Subordinate.new_for_testing(str(tmp_path / "none"), str(tmp_path / "none"))
    assert not subordinate.contains("uid", 100000)
