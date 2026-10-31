"""What dockscreen takes from the process it runs in, gathered once by the entry point.

Everything below the entry points gets these as a Runtime, so none of it reads the config file, the
caller's ids, the environment or the host's accounts on its own.
"""

import os
import sys
from collections.abc import Collection, Mapping, MutableMapping
from typing import NamedTuple

from dockscreen import messages
from dockscreen.host import config, hostusers
from dockscreen.host.dockerclient import Docker, DockerNotFound


class Runtime(NamedTuple):
    settings: config.Config
    docker: Docker                          # the real docker
    accounts: hostusers.HostAccounts
    subordinate: hostusers.Subordinate      # ranges in /etc/subuid and /etc/subgid
    me: tuple                               # the caller's real (uid, gid)
    env: MutableMapping                     # the environment, which compose and docker inherit
    home: str                               # the caller's home directory
    cwd: str                                # the directory dockscreen was started in

    @property
    def config_file(self) -> str:
        """Returns the path of the caller's own config file, which hints point to (config.user_file)."""
        return config.user_file(self.env, self.home)


def load_runtime() -> Runtime:
    """Gathers the Runtime of this process; raises config.ConfigError for a config file not to be trusted,
    and DockerNotFound if there is no real docker.

    Creates the caller's config file if it is missing (config.load_current). Warns about empty or
    relative PATH entries.
    """
    env, home, me = os.environ, os.path.expanduser("~"), (os.getuid(), os.getgid())
    _warn_about_relative_path(env)
    settings = config.load_current(env, home, me[0])
    return Runtime(
        settings=settings,
        docker=Docker(_real_docker(settings, env)),
        accounts=hostusers.HostAccounts(),
        subordinate=hostusers.Subordinate(),
        me=me,
        env=env,
        home=home,
        cwd=os.getcwd(),
    )


def _warn_about_relative_path(env: Mapping[str, str]) -> None:
    """Warns if PATH in env has empty or relative entries."""
    # docker, compose and their plugins and credential helpers look up programs on PATH too
    if any(not os.path.isabs(directory) for directory in env.get("PATH", "").split(os.pathsep)):
        messages.warning("PATH has empty or relative entries: a project directory can supply the programs "
                         "that docker and compose run")


def _real_docker(settings: config.Config, env: Mapping[str, str],
                 wrappers: Collection[str] | None = None) -> str:
    """Returns the docker to run: the one settings names, else the first one on PATH that is not a
    wrapper. Raises DockerNotFound if there is none.

    wrappers: real paths of the wrappers to skip; by default the one this process was started as.
    """
    if wrappers is None:
        wrappers = {os.path.realpath(sys.argv[0])}
    # not plain "docker" as a fallback: exec would search PATH for it and find the wrapper or ./docker
    docker = settings.docker or _find_docker(env, wrappers)
    if not docker:
        raise DockerNotFound(messages.DOCKER_NOT_FOUND)
    return docker


def _find_docker(env: Mapping[str, str], wrappers: Collection[str]) -> str | None:
    """Returns the first executable `docker` on PATH in env whose real path is not in wrappers, or None.

    Empty and relative PATH entries (an empty one means the current directory) are skipped: a
    project must not be able to supply the binary we run.
    """
    for directory in env.get("PATH", "").split(os.pathsep):
        if not os.path.isabs(directory):
            continue
        candidate = os.path.join(directory, "docker")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) \
                and os.path.realpath(candidate) not in wrappers:
            return candidate
    return None
