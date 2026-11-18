"""This module defines the Runtime class, a snapshot of the facts that dockscreen takes from the process it
runs in. The entry point gathers them once.

Everything below the entry points gets these facts as a Runtime, so none of it reads the config file, the
invoking user's ids, the environment or the host's accounts on its own.
"""

import os
import sys
from collections.abc import Collection, Mapping, MutableMapping
from typing import NamedTuple, Self

from dockscreen.host import config, hostusers
from dockscreen.host.docker import Docker, DockerNotFoundError
from dockscreen.model.settings import Config
from dockscreen.util import messages


class Runtime(NamedTuple):
    """Snapshot of the facts that dockscreen takes from the process it runs in, so that nothing below the
    entry points reads the environment, the config file or this host's accounts on its own. It holds the
    settings, the real docker, the host's accounts, and the invoking user's ids, environment and
    directories.

    Instances come from load_runtime, at the entry point.

    Attributes:
    - settings: the invoking user's settings (Config)
    - docker: the real docker (Docker)
    - accounts: the accounts on this host (HostAccounts)
    - subordinate: the ranges in /etc/subuid and /etc/subgid (SubordinateRanges)
    - me: the invoking user's real (uid, gid)
    - env: the environment, which compose and docker inherit; it must not be changed in place, and the
      method with_docker_env returns a runtime whose docker passes more variables
    - home: the invoking user's home directory
    - cwd: the directory dockscreen was started in
    """
    settings: Config
    docker: Docker
    accounts: hostusers.HostAccounts
    subordinate: hostusers.SubordinateRanges
    me: tuple
    env: MutableMapping
    home: str
    cwd: str

    @property
    def config_file(self) -> str:
        """Returns the path of the invoking user's own config file, which hints point to
        (config.user_file_path)."""
        return config.user_file_path(self.env, self.home)

    def with_docker_env(self, variables: Mapping[str, str]) -> Self:
        """Returns this runtime with variables added to the environment of the commands its docker runs.

        env, this process's own environment, stays as it is.
        """
        return self._replace(docker=self.docker.with_env(variables))


def load_runtime() -> Runtime:
    """Gathers the Runtime of this process. Raises config.ConfigError for a config file that cannot be
    trusted, and DockerNotFoundError if there is no real docker.

    Creates the user's config file if it is missing (config.load_current). Warns about empty or
    relative PATH entries.
    """
    env = os.environ
    home = os.path.expanduser("~")
    me = (os.getuid(), os.getgid())
    _warn_about_relative_path(env)
    settings = config.load_current(env, home, me[0])
    return Runtime(
        settings=settings,
        docker=Docker(_real_docker_path(settings, env)),
        accounts=hostusers.HostAccounts(),
        subordinate=hostusers.SubordinateRanges(),
        me=me,
        env=env,
        home=home,
        cwd=os.getcwd(),
    )


def _warn_about_relative_path(env: Mapping[str, str]) -> None:
    """Warns if PATH in env has empty or relative entries."""
    # docker, compose and their plugins and credential helpers look up programs on PATH too
    if any(not os.path.isabs(directory) for directory in env.get("PATH", "").split(os.pathsep)):
        messages.print_warning("PATH has empty or relative entries: a project directory can supply the "
                               "programs that docker and compose run")


def _real_docker_path(settings: Config, env: Mapping[str, str],
                      wrappers: Collection[str] | None = None) -> str:
    """Returns the path of the docker to run: the docker that settings names, else the first docker on PATH
    that is not a wrapper. Raises DockerNotFoundError if there is none.

    wrappers: real paths of the wrappers to skip; by default the wrapper that this process was started as.
    """
    if wrappers is None:
        wrappers = {os.path.realpath(sys.argv[0])}
    # not plain "docker" as a fallback: exec would search PATH for it and find the wrapper or ./docker
    docker_path = settings.docker or _find_docker(env, wrappers)
    if not docker_path:
        raise DockerNotFoundError(messages.DOCKER_NOT_FOUND_MESSAGE)
    return docker_path


def _find_docker(env: Mapping[str, str], wrappers: Collection[str]) -> str | None:
    """Returns the first executable `docker` on PATH in env whose real path is not in wrappers, or None.

    This skips empty and relative PATH entries (an empty entry means the current directory): a project
    must not be able to supply the binary dockscreen runs.
    """
    for directory in env.get("PATH", "").split(os.pathsep):
        if not os.path.isabs(directory):
            continue
        candidate = os.path.join(directory, "docker")
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK) \
                and os.path.realpath(candidate) not in wrappers:
            return candidate
    return None
