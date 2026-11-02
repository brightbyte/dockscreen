"""This module defines what the groups of the policy's rules share: the settings they read (RuleBase), what
they judge a service as (Subject), the allowlist of keys (unknown_keys) and the judging of paths
(is_inside).
"""

import os
from collections.abc import Collection, Iterable, Mapping, Sequence
from typing import Any, Protocol

from dockscreen.host import config as configuration
from dockscreen.model.origin import Origin
from dockscreen.screen import idrules


class Subject(Protocol):
    """Service as Policy.check_service judges it: one of a compose project (project.Service), or what a
    container asks for, read back as one (container.Container).
    """

    @property
    def definition(self) -> dict[str, Any]:
        """Returns its compose service keys."""
        ...

    @property
    def directory(self) -> str:
        """Returns the directory its relative paths and bind mounts are judged against."""
        ...

    @property
    def reaches_host(self) -> bool:
        """Tells whether it reaches host files (mounts.service_reaches_host)."""
        ...

    def origin_of(self, key: str) -> Origin:
        """Returns where the value of key comes from."""
        ...


class RuleBase:
    """Settings that every group of rules reads, which Policy holds, and what they make of them."""
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

    def mount_roots(self, directory: str) -> tuple[str, ...]:
        """Returns where bind mounts may come from for a project in directory: directory, then the configured
        mount_dirs.
        """
        return (directory, *self.extra_dirs)

    def _outside(self, subject: str, directory: str) -> str:
        """Returns the problem that subject is outside the mount roots of a project in directory, with how the
        config file can allow it.
        """
        text = f"{subject} is outside {_roots_text(self.mount_roots(directory))}"
        if self.config_file:
            text += (f"; to allow it, add a directory that contains it to mount_dirs under "
                     f"[projects.\"{directory}\"] in {self.config_file}")
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


def _roots_text(mount_roots: Sequence[str]) -> str:
    """Names mount_roots for a message."""
    directory, *extra = mount_roots
    return f"{directory}" + (" and the configured mount_dirs" if extra else "")


def is_inside_any(path: str, roots: Iterable[str]) -> bool:
    """Tells whether path is inside one of roots (is_inside)."""
    return any(is_inside(path, root) for root in roots)


def is_inside(path: str, root: str) -> bool:
    """Tells whether path, resolved relative to root and through symlinks, is root or below it."""
    real_root = os.path.realpath(root)
    real = os.path.realpath(os.path.join(real_root, path))
    return os.path.commonpath([real_root, real]) == real_root
