"""This module provides functions for finding out what screening needs to know about the services of a
compose project besides their definition: which of them start, which user the image of each started service
that sets no user would run it as (imageusers), and the images that an image section of the config file
names, with where they were pulled from, which shows whether the section applies (ServiceImages).

A project file is untrusted, so a service without `user:` cannot just be assumed to run as root or as
whatever its image says; a service whose user the command line chose (`run -u`) runs as that one, so its
image is not asked. What follows is the policy's and decisions': what is accepted is pinned in the
generated config only, with the image that was checked, so that neither the files the project owns nor
`harden` output turn off the project's updates; a service that is not started, or whose user the command
line chose, gets the default user in case it does get started without it.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.compose import imageusers
from dockscreen.host import config as configuration
from dockscreen.host.docker import DockerError
from dockscreen.model.image import Image, Inspected
from dockscreen.model.project import Project, ServiceImages
from dockscreen.screen.finding import Finding, failure_of
from dockscreen.screen.screener import Screener


def prepare(command: Sequence[str], project: Project, args: Sequence[str], screener: Screener,
            chosen: frozenset[str] = frozenset()) -> tuple[ServiceImages | None, list[Finding]]:
    """Finds out what screening needs to know about project's services, for the policy to decide on
    (Screener.decide): pulls and builds the images of the services that start as `up` would, and looks at
    those of the services that set no user.

    Returns (what was found of the images, the failures to acquire them), None for the first if one failed.

    Parameters:
    - command: the compose command line (up to the subcommand) on the project's definition, as it will run
    - project: the hardened project
    - args: the arguments after the subcommand, which name services and may carry --build or --pull
    - screener: the Screener to pull, build, decide and run with
    - chosen: services whose user the command line chooses (`run -u`); their images are not looked at
    """
    config = project.definition
    try:
        started = _services_to_run(command, config, args, screener)
        looked_at = (started - chosen) & project.services_without_user
        inspected, failures = imageusers.find(command, project, started, looked_at, args, screener)
    except DockerError as e:
        return None, [failure_of(e)]
    if failures:
        return None, failures
    found = {**_find_section_images(config, screener),
             **{name: image.image for name, image in inspected.items() if isinstance(image, Inspected)}}
    return ServiceImages(found, inspected), []


def _find_section_images(config: dict[str, Any], screener: Screener) -> dict[str, Image]:
    """Finds the images of the services that an image section of the config file names, with where they
    were pulled from, which shows whether the section applies; the checks before the images were there
    trusted the name alone.

    Returns {service: image} for those that are here.
    """
    settings = screener.runtime.settings
    found = {}
    for name, service in (config.get("services") or {}).items():
        image, built = imageusers.image_name(config, name, service), "build" in service
        if configuration.name_matches(settings, image, built) is None:
            continue
        try:
            inspected = screener.docker.inspect_image(image)
        except DockerError:
            continue  # not there: the section does not apply, and the final check says what that means
        found[name] = Image(image, inspected.get("Id"), built, tuple(inspected.get("RepoDigests") or ()))
    return found


def _services_to_run(command: Sequence[str], config: dict[str, Any], args: Sequence[str],
                     screener: Screener) -> frozenset[str]:
    """Determines the services the command starts: those in the active profiles, plus any named in args.

    Raises DockerError if compose cannot list them.
    """
    result = screener.docker.capture([*command, "config", "--services"])
    if result.returncode != 0:
        raise DockerError("docker compose config --services failed")
    services = config.get("services") or {}
    return frozenset(set(result.stdout.split()) | {a for a in args if a in services})
