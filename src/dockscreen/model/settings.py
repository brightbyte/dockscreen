"""This module defines the Config class, dockscreen's settings as the config files give them. It also
defines SectionMatch, the record of the image section that applies to an image.

The module host.config reads the files; the module policy.sections works out which sections apply to an
image and to a project.
"""

from types import MappingProxyType
from typing import NamedTuple


class ConfigSection(NamedTuple):
    """Record of the settings of one image or project section of the config files. It holds the settings the
    section sets; None, or () for a list, leaves a setting to the levels above.

    Attributes:
    - user, default_user, default_home, nobody_range, mount_dirs, security_opts: as in Config
    """
    user: tuple[int, int] | None = None
    default_user: tuple[int, int] | None = None
    default_home: str | None = None
    nobody_range: tuple[int, int] | None = None
    mount_dirs: tuple = ()
    security_opts: tuple = ()


class Config(NamedTuple):
    """Record of dockscreen's settings, as the config files give them, with their sections per image
    repository and per project directory. It holds the top-level settings, filled in with the defaults, the
    sections, and which settings a file set.

    The user's settings come from host.config.load_current. The settings that apply to one image and
    project come from policy.sections.effective_settings; they have no sections of their own.

    Attributes:
    - user: the (uid, gid) an image runs as when nothing chose a user, or None
    - default_user: the (uid, gid) that replaces an image's root user
    - default_home: the HOME of the default user; "" leaves HOME alone
    - nobody_range: the inclusive range of ids any image or project may use
    - mount_dirs: the absolute directories bind mounts may come from
    - security_opts: the security options allowed besides no-new-privileges
    - docker: the absolute path of the real docker, or None
    - images: the image sections, by normalised repository (ConfigSection)
    - projects: the project sections, by absolute directory (ConfigSection)
    - configured_keys: the names of the settings a config file sets; the others are defaults
    """
    user: tuple[int, int] | None = None
    default_user: tuple[int, int] = (65534, 65534)
    default_home: str = "/tmp"
    nobody_range: tuple[int, int] = (65530, 65534)
    mount_dirs: tuple = ()
    security_opts: tuple = ()
    docker: str | None = None
    images: MappingProxyType = MappingProxyType({})
    projects: MappingProxyType = MappingProxyType({})
    configured_keys: frozenset = frozenset()


class SectionMatch(NamedTuple):
    """Record of the image section of the config file that applies to an image, or of the reason that the
    section for the image's repository does not apply.

    Instances come from policy.sections.section_for; NO_SECTION stands for a target that is not an image.

    Attributes:
    - repository: the repository of the image section that applies, or None
    - problem: the reason that a section for the image's repository does not apply, for audit; None if
      there is none
    """
    repository: str | None
    problem: str | None


NO_SECTION = SectionMatch(None, None)  # for a target that is not an image, or an image that no section is for


def all_mount_dirs(config: Config) -> tuple[str, ...]:
    """Returns every mount dir the config names, the top level's and every section's, once each."""
    sections = [*config.images.values(), *config.projects.values()]
    return tuple(dict.fromkeys([*config.mount_dirs, *(d for s in sections for d in s.mount_dirs)]))
