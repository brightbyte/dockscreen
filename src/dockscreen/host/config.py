"""This module provides functions for reading dockscreen's settings (model.settings.Config) from TOML files
that only the user or root can write.

dockscreen trusts the files completely, so it reads them only when nothing but their owner could have
put their content there: the user or root must own the file and every directory above it, and group
and others may not write them, as ssh's StrictModes requires. A project cannot configure dockscreen;
environment variables do not configure it either.

The user's file overrides the system file key by key, and [images] and [projects] section by section.
dockscreen creates a missing user file from config.template.toml, with every setting commented out, so
that it shows the defaults without overriding the system file.

The settings can also be given per image (`[images."REPOSITORY"]`) and per project
(`[projects."DIRECTORY"]`); which of them apply to a target is the policy's (policy.sections).
"""

import importlib.resources
import os
import stat
import tomllib
from collections.abc import Callable, Iterable, Mapping
from types import MappingProxyType
from typing import Any

from dockscreen.model.image import split_reference
from dockscreen.model.settings import Config, ConfigSection
from dockscreen.util import ids, messages

SYSTEM_FILE = "/etc/dockscreen/config.toml"
# What the top level, an image section and a project section may set.
SETTINGS = frozenset({"user", "default_user", "default_home", "nobody_range", "mount_dirs", "security_opts"})
KEYS = SETTINGS | {"docker", "images", "projects"}


class ConfigError(Exception):
    """Exception raised when a config file cannot be trusted or read, which stops dockscreen from running."""


def user_file(env: Mapping[str, str], home: str) -> str:
    """Returns the path of the user's config file, $XDG_CONFIG_HOME/dockscreen/config.toml.

    This ignores an XDG_CONFIG_HOME in env that is not absolute, as XDG says, in favour of home/.config:
    the system would read it relative to the current directory, which is the project's, so a project could
    supply the config that dockscreen trusts completely.

    Parameters:
    - env: the user's environment
    - home: the user's home directory
    """
    base = env.get("XDG_CONFIG_HOME", "")
    if not os.path.isabs(base):
        base = os.path.join(home, ".config")
    return os.path.join(base, "dockscreen", "config.toml")


def load_current(env: Mapping[str, str], home: str, uid: int) -> Config:
    """Loads the configuration of the user with this environment, home directory and uid.

    Creates the user's file if it is missing, with a notice. Raises ConfigError as _load does.
    """
    path = user_file(env, home)
    if _create_user_file(path):
        messages.notice(f"created {path}, which shows the defaults")
    return _load([SYSTEM_FILE, path], uid)


def _create_user_file(path: str) -> bool:
    """Writes the template to path, with its directories, if nothing is there; returns whether it did.

    Failing to write it is not an error: dockscreen runs with the defaults. An existing file, or a
    symlink in its place, is never touched: following a link someone placed there would write the
    template to the link's target, as the user.
    """
    template = importlib.resources.files("dockscreen.host").joinpath("config.template.toml").read_bytes()
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except OSError:
        return False
    with os.fdopen(fd, "wb") as f:
        f.write(template)
    return True


def _load(paths: Iterable[str], uid: int, check: Callable[[str, int], None] | None = None) -> Config:
    """Reads the files in paths and merges them over the defaults, later ones winning; skips missing ones.

    check(path, uid) raises ConfigError for a file that cannot be trusted (_strict_modes by default).
    Raises ConfigError too for a file that cannot be read or parsed, or that sets something invalid.
    """
    check = check or _strict_modes
    config = Config()
    for path in paths:
        data = _read(path, uid, check)
        if data is not None:
            config = _merge(config, path, data)
    return config


def _merge(config: Config, path: str, data: dict[str, Any]) -> Config:
    """Returns config with data, read from path, over it: its keys replace, its sections replace by name.

    Raises ConfigError, naming path, for an unknown key or an invalid value.
    """
    unknown = sorted(set(data) - KEYS)
    if unknown:
        raise ConfigError(f"{path}: unknown key {unknown[0]!r}")
    images_ = {_repository_key(path, name): _section(path, f"images {name!r}", value)
               for name, value in _table(path, "images", data.get("images", {})).items()}
    projects = {_project_key(path, name): _section(path, f"projects {name!r}", value)
                for name, value in _table(path, "projects", data.get("projects", {})).items()}
    top = _section(path, "", {k: v for k, v in data.items() if k in SETTINGS})
    changes = {key: value for key, value in top._asdict().items() if key in data}
    if "docker" in data:
        # a relative path would be found from the current directory, which is the project's
        if not isinstance(data["docker"], str) or not os.path.isabs(data["docker"]):
            raise ConfigError(f"{path}: docker must be an absolute path")
        changes["docker"] = data["docker"]
    return config._replace(**changes, images=MappingProxyType({**config.images, **images_}),
                           projects=MappingProxyType({**config.projects, **projects}),
                           configured=config.configured | (set(data) & SETTINGS))


def _table(path: str, key: str, value: object) -> dict[str, Any]:
    """Returns value if it is a table; raises ConfigError naming key in path otherwise."""
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: {key} must be a table of sections")
    return value


def _section(path: str, where: str, data: object) -> ConfigSection:
    """Returns the ConfigSection that data sets; raises ConfigError for an unknown key or an invalid value.

    where: names the section in errors ("" for the top level).
    """
    prefix = f"{path}: {where} " if where else f"{path}: "
    if not isinstance(data, dict):
        raise ConfigError(f"{prefix}must be a table")
    unknown = sorted(set(data) - SETTINGS)
    if unknown:
        raise ConfigError(f"{prefix}unknown key {unknown[0]!r}")
    fields: dict[str, Any] = {}
    for key in ("user", "default_user"):
        if key in data:
            fields[key] = _user_value(path, f"{where} {key}".strip(), data[key])
    if "default_home" in data:
        value = data["default_home"]
        if not isinstance(value, str) or (value and not os.path.isabs(value)):
            raise ConfigError(f"{prefix}default_home must be an absolute path, or \"\" to leave HOME alone")
        fields["default_home"] = value
    if "nobody_range" in data:
        fields["nobody_range"] = _id_range(path, data["nobody_range"])
    if "mount_dirs" in data:
        value = data["mount_dirs"]
        if not isinstance(value, list) or not all(isinstance(d, str) and os.path.isabs(d) for d in value):
            raise ConfigError(f"{prefix}mount_dirs must be a list of absolute paths")
        fields["mount_dirs"] = tuple(value)
    if "security_opts" in data:
        value = data["security_opts"]
        if not isinstance(value, list) or not all(isinstance(o, str) and o for o in value):
            raise ConfigError(f"{prefix}security_opts must be a list of security options")
        fields["security_opts"] = tuple(value)
    return ConfigSection(**fields)


def _read(path: str, uid: int, check: Callable[[str, int], None]) -> dict[str, Any] | None:
    """Returns the TOML in path, or None if there is no file; check(path, uid) must pass for the file read.

    Raises ConfigError if it does not, or the file cannot be read or parsed.
    """
    try:
        with open(path, "rb") as f:
            check(path, uid)
            # check looked at the path; what is read is the file already open, so they must be the same
            opened, checked = os.fstat(f.fileno()), os.stat(path)
            if (opened.st_dev, opened.st_ino) != (checked.st_dev, checked.st_ino):
                raise ConfigError(f"{path}: the file was replaced while it was read")
            return tomllib.load(f)
    except FileNotFoundError:
        return None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    except OSError as e:
        raise ConfigError(f"{path}: {e.strerror}") from None


def _strict_modes(path: str, uid: int, stat_path: Callable[[str], os.stat_result] = os.stat) -> None:
    """Checks, like ssh's StrictModes, that path and every directory above it are owned by uid or root
    and writable by nobody else; raises ConfigError if not.

    Otherwise anyone who could write there could configure dockscreen.
    """
    current = os.path.realpath(path)
    while True:
        info = stat_path(current)
        if info.st_uid not in (uid, 0):
            raise ConfigError(f"{path}: {current} is owned by uid {info.st_uid}, not by you or root")
        if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ConfigError(f"{path}: {current} is writable by group or others")
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent


def _user_value(path: str, key: str, value: object) -> tuple[int, int]:
    """Returns (uid, gid) for value "uid:gid"; raises ConfigError unless both are numeric ids."""
    user = ids.parse_user(value) if isinstance(value, str) else None
    if user is None:
        raise ConfigError(f"{path}: {key} must be \"uid:gid\" with numeric ids, not {value!r}")
    return user


def _id_range(path: str, value: Any) -> tuple[int, ...]:
    """Returns value as an inclusive (low, high); raises ConfigError unless it leaves out root and the ids
    that mean "no id".
    """
    valid = isinstance(value, list) and len(value) == 2 and all(isinstance(v, int) for v in value)
    if not (valid and 0 < value[0] <= value[1] and not any(value[0] <= n <= value[1] for n in ids.NO_ID)
            and value[1] < max(ids.NO_ID)):  # also keeps out ids beyond 32 bits
        raise ConfigError(f"{path}: nobody_range must be [low, high] with 0 < low <= high < 4294967295, "
                          "leaving out 65535")
    return tuple(value)


def _repository_key(path: str, name: str) -> str:
    """Returns the normalised repository an image section names; raises ConfigError for a tag or digest."""
    try:
        repository, tag, digest = split_reference(name)
    except ValueError as e:
        raise ConfigError(f"{path}: images {name!r}: {e}") from None
    if tag or digest:
        raise ConfigError(f"{path}: images {name!r} names a repository; leave out the tag or digest")
    return repository


def _project_key(path: str, name: str) -> str:
    """Returns the normalised directory a project section names; raises ConfigError unless it is absolute."""
    if not os.path.isabs(name):
        raise ConfigError(f"{path}: projects {name!r} must be an absolute directory")
    return os.path.normpath(name)
