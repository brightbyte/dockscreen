"""This module defines the parts that the groups of the policy's rules have in common: the base class with
the settings they read, and the interface of the service they judge. It also provides functions for checking
keys against an allowlist and paths against a directory."""

import os
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol

from dockscreen.model.origin import Origin
from dockscreen.model.settings import SectionMatch

if TYPE_CHECKING:
    from dockscreen.policy.rules.userrules import IdFacts


class JudgedService(Protocol):
    """Protocol of a service as Policy.check_service judges it. A compose service (project.Service)
    implements it, and so does a container read back as a service (container.Container). It gives the
    service's keys, the directory that the policy judges them against, whether the service reaches host
    files, and the origin of each key's value.
    """

    @property
    def definition(self) -> dict[str, Any]:
        """Returns its compose service keys."""
        ...

    @property
    def directory(self) -> str | None:
        """Returns the directory that the policy judges its relative paths and bind mounts against. Returns
        None for a container whose directory is not known; then only the configured mount_dirs allow its bind
        mounts. Only a compose service has keys with relative paths (directory_of).
        """
        ...

    @property
    def reaches_host(self) -> bool:
        """Tells whether it reaches host files (mounts.service_reaches_host)."""
        ...

    def origin_of(self, key: str) -> Origin:
        """Returns where the value of key comes from."""
        ...


class RuleBase:
    """Base class of the mixins of Policy, not used on its own. It declares the settings that their rules
    read, which Policy holds and documents. It also provides what follows from those settings for every
    group of rules.

    The id rules judge by the settings and host facts about ids (userrules.IdFacts). These are one object,
    ids, for every group of rules to read.
    """
    ids: "IdFacts"
    extra_dirs: tuple
    trust: frozenset[Origin]
    config_file: str | None
    security_opts: tuple
    configured_user: tuple | None
    nobody_range: tuple[int, int]
    default_user: tuple[int, int]
    default_home: str
    default_origin: Origin
    section: SectionMatch

    def mount_roots(self, directory: str | None) -> tuple[str, ...]:
        """Returns the directories that bind mounts may come from, for a project in directory: directory
        first, then the configured mount_dirs. For None, it returns only the configured mount_dirs.

        Parameters:
        - directory: the project directory; None for no known directory
        """
        return (*([directory] if directory is not None else []), *self.extra_dirs)

    def _outside_problem(self, subject: str, directory: str | None) -> str:
        """Returns the problem that subject is outside the mount roots of a project in directory, with a hint
        on allowing it in the config file. directory is None if no directory is known.
        """
        text = f"{subject} is outside {_roots_text(directory, self.extra_dirs)}"
        if self.config_file:
            config_location = f" under [projects.\"{directory}\"]" if directory is not None else ""
            text += (f"; to allow it, add a directory that contains it to mount_dirs{config_location} "
                     f"in {self.config_file}")
        return text


def unknown_key_problems(mapping: Mapping[str, Any], allowed_keys: Collection[str], key_kind: str,
                         allows_extensions: bool = True) -> list[str]:
    """Returns a problem for each key of mapping not in allowed_keys; `x-` keys pass unless allows_extensions
    is False.

    Parameters:
    - mapping: the keys to check, with their values
    - allowed_keys: the keys that may be there
    - key_kind: names the kind of key in the problems
    - allows_extensions: `x-` keys pass
    """
    return [
        f"{key_kind} {key!r} is not on the allow list"
        for key in mapping
        if key not in allowed_keys and not (allows_extensions and str(key).startswith("x-"))
    ]


def _roots_text(directory: str | None, extra_dirs: Sequence[str]) -> str:
    """Names the mount roots of a project in directory, with extra_dirs, for a message. directory is None if
    no directory is known.
    """
    if directory is None:
        return "the configured mount_dirs" if extra_dirs else "the configured mount_dirs, which are none"
    return f"{directory}" + (" and the configured mount_dirs" if extra_dirs else "")


def directory_of(service: JudgedService) -> str:
    """Returns the directory of a service that has keys with relative paths, which only a compose service
    has. container.as_service reads a container's requests back without relative paths, so the directory of
    a container may be unknown.
    """
    assert service.directory is not None, "only a compose service has keys with relative paths"
    return service.directory


def is_inside_any(path: str, roots: Iterable[str]) -> bool:
    """Tells whether path is inside one of roots (is_inside)."""
    return any(is_inside(path, root) for root in roots)


def is_inside(path: str, root: str) -> bool:
    """Tells whether path, resolved relative to root and through symlinks, is root or below it.

    Docker follows symlinks when it mounts or reads a path, so a project that contains `data -> /` must not
    pass with `./data`. Resolving also undoes `..` and repeated slashes. The result holds for the file system
    as it is when the check runs. A container that can write the project could swap a directory for a link
    afterwards (docs/design.md, Known gaps).
    """
    real_root = os.path.realpath(root)
    real_path = os.path.realpath(os.path.join(real_root, path))
    return os.path.commonpath([real_root, real_path]) == real_root
