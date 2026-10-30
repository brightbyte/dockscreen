"""What dockscreen takes from the process it runs in, gathered once by the entry point.

Everything below the entry points gets these as a Runtime, so none of it reads the config file, the
caller's ids, the environment or the host's accounts on its own.
"""

import os
import sys
from collections.abc import MutableMapping
from typing import NamedTuple

from dockscreen import config, hostusers, idrules
from dockscreen.dockerclient import Docker


class Runtime(NamedTuple):
    settings: config.Config
    docker: Docker                          # the real docker
    accounts: hostusers.HostAccounts
    subordinate: idrules.Subordinate        # ranges in /etc/subuid and /etc/subgid
    me: tuple                               # the caller's real (uid, gid)
    env: MutableMapping                     # the environment, which compose and docker inherit
    home: str                               # the caller's home directory
    cwd: str                                # the directory dockscreen was started in

    def rules(self, allow_me=False):
        """Returns the id rules for the config file's settings; allow_me: the caller's own ids are allowed."""
        return idrules.Rules(self.me, allow_me, self.settings.nobody_range, self.settings.default_user,
                             self.accounts, self.subordinate)

    @property
    def config_file(self):
        """Returns the path of the caller's own config file, which hints point to (config.user_file)."""
        return config.user_file(self.env, self.home)


def load_runtime():
    """Gathers the Runtime of this process; raises config.ConfigError for a config file not to be trusted.

    Creates the caller's config file if it is missing (config.load_current).
    """
    env, home, me = os.environ, os.path.expanduser("~"), (os.getuid(), os.getgid())
    settings = config.load_current(env, home, me[0])
    return Runtime(
        settings=settings,
        docker=Docker(real_docker(settings, env)),
        accounts=hostusers.HostAccounts(),
        subordinate=idrules.Subordinate(),
        me=me,
        env=env,
        home=home,
        cwd=os.getcwd(),
    )


def real_docker(settings, env, wrappers=None):
    """Returns the docker to run: the one settings names, else the first one on PATH that is not a
    wrapper, else plain "docker", so that exec reports the usual error.

    wrappers: real paths of the wrappers to skip; by default the one this process was started as.
    """
    if wrappers is None:
        wrappers = {os.path.realpath(sys.argv[0])}
    return settings.docker or find_docker(env, wrappers) or "docker"


def find_docker(env, wrappers):
    """Returns the first executable `docker` on PATH in env whose real path is not in wrappers, or None.

    Empty PATH entries (meaning the current directory) are skipped: a hostile
    project must not be able to supply the binary we run.
    """
    for directory in env.get("PATH", "").split(os.pathsep):
        if not directory:
            continue
        candidate = os.path.join(directory, "docker")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) \
                and os.path.realpath(candidate) not in wrappers:
            return candidate
    return None
