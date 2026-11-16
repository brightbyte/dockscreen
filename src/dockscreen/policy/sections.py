"""This module provides functions for working out which sections of the config files apply to an image and a
project, and the settings that result.

The config file can give the settings per image (`[images."REPOSITORY"]`) and per project
(`[projects."DIRECTORY"]`).
They apply in that order, after the top level (effective): a single value replaces the one before, a list
is added to the ones before.

An image section names a repository: it trusts the image's maintainer, not one image. A name alone
proves nothing, because anyone can build or tag an image locally under any name, so an image matches only
if docker recorded that it pulled the image from that repository (a repo digest), and never for a service
that builds its image from a Dockerfile (section_for).
"""

import os
from collections.abc import Iterable
from types import MappingProxyType

from dockscreen.model.image import repository
from dockscreen.model.settings import Config, ConfigSection, SectionMatch


def effective(config: Config, repository: str | None = None, directory: str | None = None) -> Config:
    """Returns the settings for an image pulled from repository, in a project in directory.

    They are the top level's, amended by the image's section, then by the sections of the projects that
    directory is in, outermost first. The
    result has no sections of its own.

    Parameters:
    - config: the settings of the config file
    - repository: the image's repository; None for no image section
    - directory: the project directory; None for no project section
    """
    sections = [config.images[repository]] if repository in config.images else []
    if directory is not None:
        real = os.path.realpath(directory)
        roots = {d: os.path.realpath(d) for d in config.projects}
        matching = [d for d, root in roots.items() if os.path.commonpath([real, root]) == root]
        sections += [config.projects[d] for d in sorted(matching, key=lambda d: len(roots[d]))]
    result = config._replace(images=MappingProxyType({}), projects=MappingProxyType({}))
    for section in sections:
        result = _amend(result, section)
    return result


def _amend(config: Config, section: ConfigSection) -> Config:
    """Returns config with section applied: the values it sets replace, the lists it gives are added to."""
    changes = {key: getattr(section, key) for key in ("user", "default_user", "default_home", "nobody_range")
               if getattr(section, key) is not None}
    lists = [key for key in ("mount_dirs", "security_opts") if getattr(section, key)]
    configured = frozenset({*config.configured, *changes, *lists})
    for key in ("mount_dirs", "security_opts"):
        before = getattr(config, key)
        changes[key] = (*before, *(v for v in getattr(section, key) if v not in before))
    return config._replace(**changes, configured=configured)


def section_for(config: Config, reference: str, repo_digests: Iterable[str] | None, built: bool
                ) -> SectionMatch:
    """Determines which image section of the config file applies to this image, as a SectionMatch.

    Parameters:
    - config: the settings of the config file
    - reference: the image name the service or command line uses
    - repo_digests: the image's RepoDigests (docker image inspect): where it was pulled from
    - built: the service builds the image from a Dockerfile
    """
    name = repository(reference)
    if name not in config.images:
        return SectionMatch(None, None)
    if built:
        return SectionMatch(None, f"the config has a section for {name}, but the service builds its image")
    if not any(repository(d) == name for d in repo_digests or []):
        return SectionMatch(
            None, f"the config has a section for {name}, but this image was not pulled from there")
    return SectionMatch(name, None)


def name_matches(config: Config, reference: str, built: bool) -> str | None:
    """Returns the repository of the image section the name alone points to, or None if there is none or
    the service builds the image. The name proves nothing: this is for before the image is there.

    Parameters:
    - config: the settings of the config file
    - reference: the image name
    - built: a compose service builds the image
    """
    name = repository(reference)
    return name if name in config.images and not built else None
