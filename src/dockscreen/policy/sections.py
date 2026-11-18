"""This module provides functions for working out which sections of the config files apply to an image and a
project, and the settings that result.

The config file can give the settings per image (`[images."REPOSITORY"]`) and per project
(`[projects."DIRECTORY"]`). The sections apply in that order, after the top level (effective_settings). A
single value replaces the value before it; a list is added to the lists before it.

An image section names a repository: it trusts the image's maintainer, not one image. A name alone
proves nothing, because anyone can build or tag an image locally under any name. So an image matches a
section only if docker recorded that it pulled the image from that repository (a repo digest). It never
matches for a service that builds its image from a Dockerfile (section_for).
"""

import os
from collections.abc import Iterable
from types import MappingProxyType

from dockscreen.model.image import repository
from dockscreen.model.settings import Config, ConfigSection, SectionMatch


def effective_settings(config: Config, repository: str | None = None, directory: str | None = None) -> Config:
    """Returns the settings for an image pulled from repository, in the project whose directory is
    directory.

    They are the top-level settings, amended first by the image's section, then by the sections of the
    projects that contain directory, outermost first. The result has no sections of its own.

    Parameters:
    - config: the settings of the config file
    - repository: the image's repository; None for no image section
    - directory: the project directory; None for no project section
    """
    sections = [config.images[repository]] if repository in config.images else []
    if directory is not None:
        real_directory = os.path.realpath(directory)
        roots = {d: os.path.realpath(d) for d in config.projects}
        matching_directories = [d for d, root in roots.items()
                                if os.path.commonpath([real_directory, root]) == root]
        sections += [config.projects[d] for d in sorted(matching_directories, key=lambda d: len(roots[d]))]
    result = config._replace(images=MappingProxyType({}), projects=MappingProxyType({}))
    for section in sections:
        result = _amend(result, section)
    return result


def _amend(config: Config, section: ConfigSection) -> Config:
    """Returns config with section applied: the values it sets replace those in config, and the lists it
    gives are added to those in config.
    """
    changes = {key: getattr(section, key) for key in ("user", "default_user", "default_home", "nobody_range")
               if getattr(section, key) is not None}
    list_keys = [key for key in ("mount_dirs", "security_opts") if getattr(section, key)]
    configured_keys = frozenset({*config.configured_keys, *changes, *list_keys})
    for key in ("mount_dirs", "security_opts"):
        previous_values = getattr(config, key)
        changes[key] = (*previous_values, *(v for v in getattr(section, key) if v not in previous_values))
    return config._replace(**changes, configured_keys=configured_keys)


def section_for(config: Config, reference: str, repo_digests: Iterable[str] | None, is_built: bool
                ) -> SectionMatch:
    """Determines which image section of the config file applies to this image, as a SectionMatch.

    Parameters:
    - config: the settings of the config file
    - reference: the image name the service or command line uses
    - repo_digests: the image's RepoDigests (docker image inspect), which say where docker pulled it from
    - is_built: the service builds the image from a Dockerfile
    """
    name = repository(reference)
    if name not in config.images:
        return SectionMatch(None, None)
    if is_built:
        return SectionMatch(None, f"the config has a section for {name}, but the service builds its image")
    if not any(repository(d) == name for d in repo_digests or []):
        return SectionMatch(
            None, f"the config has a section for {name}, but this image was not pulled from there")
    return SectionMatch(name, None)


def repository_for_name(config: Config, reference: str, is_built: bool) -> str | None:
    """Returns the repository of the image section that the name alone points to. Returns None if there is
    no such section, or if the service builds the image. The name proves nothing, so this is only for the
    time before the image is there.

    Parameters:
    - config: the settings of the config file
    - reference: the image name
    - is_built: a compose service builds the image
    """
    name = repository(reference)
    return name if name in config.images and not is_built else None
