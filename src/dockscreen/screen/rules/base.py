"""This module defines what the groups of the policy's rules have in common: the base class with the settings
they read, the interface of the service they judge, and functions for checking keys against an allowlist and
paths against a directory."""

import os
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any, Protocol

from dockscreen.host import config as configuration
from dockscreen.model.origin import Origin
from dockscreen.screen import idrules


class Subject(Protocol):
    """Protocol of a service as Policy.check_service judges it, which a compose service (project.Service) and
    a container read back as one (container.Container) both implement. It gives the service's keys, the
    directory they are judged against, whether it reaches host files, and where each key's value comes from.
    """

    @property
    def definition(self) -> dict[str, Any]:
        """Returns its compose service keys."""
        ...

    @property
    def directory(self) -> str | None:
        """Returns the directory its relative paths and bind mounts are judged against; None for a container
        whose directory is not known, whose bind mounts only the configured mount_dirs allow. Only a compose
        service has keys with relative paths (directory_of).
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
    """Base class of the mixins of Policy, not used on its own. It declares the settings their rules read,
    which Policy holds and documents, and what follows from them for every group of rules.
    """
    ids: idrules.Rules
    extra_dirs: tuple
    trust: frozenset[Origin]
    config_file: str | None
    security_opts: tuple
    configured_user: tuple | None
    default_user: tuple[int, int]
    default_home: str
    default_origin: Origin
    section: configuration.Match

    def mount_roots(self, directory: str | None) -> tuple[str, ...]:
        """Returns where bind mounts may come from for a project in directory: directory, then the configured
        mount_dirs; only those for None, no known directory.
        """
        return (*([directory] if directory is not None else []), *self.extra_dirs)

    def _outside(self, subject: str, directory: str | None) -> str:
        """Returns the problem that subject is outside the mount roots of a project in directory (None: none
        known), with how the config file can allow it.
        """
        text = f"{subject} is outside {_roots_text(directory, self.extra_dirs)}"
        if self.config_file:
            where = f" under [projects.\"{directory}\"]" if directory is not None else ""
            text += (f"; to allow it, add a directory that contains it to mount_dirs{where} "
                     f"in {self.config_file}")
        return text


def unknown_keys(mapping: Mapping[str, Any], allowed: Collection[str], what: str,
                 extensions: bool = True) -> list[str]:
    """Returns a problem for each key of mapping not in allowed; `x-` keys pass unless extensions is False.

    what: names the kind of key in the problems.
    """
    return [
        f"{what} {key!r} is not on the allow list"
        for key in mapping
        if key not in allowed and not (extensions and str(key).startswith("x-"))
    ]


def _roots_text(directory: str | None, extra_dirs: Sequence[str]) -> str:
    """Names the mount roots of a project in directory (None: none known), with extra_dirs, for a message."""
    if directory is None:
        return "the configured mount_dirs" if extra_dirs else "the configured mount_dirs, which are none"
    return f"{directory}" + (" and the configured mount_dirs" if extra_dirs else "")


def directory_of(service: Subject) -> str:
    """Returns the directory of a service that has keys with relative paths: a compose service. What a
    container asks for is read back without any (container.as_service), so its directory may be unknown.
    """
    assert service.directory is not None, "only a compose service has keys with relative paths"
    return service.directory


def is_inside_any(path: str, roots: Iterable[str]) -> bool:
    """Tells whether path is inside one of roots (is_inside)."""
    return any(is_inside(path, root) for root in roots)


def is_inside(path: str, root: str) -> bool:
    """Tells whether path, resolved relative to root and through symlinks, is root or below it."""
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(real_root, path))
    return os.path.commonpath([real_root, real]) == real_root
