"""This module provides functions for finding out what screening needs to know about the services of a
compose project besides their definition: which of them start, which user the image of each started service
that sets no user would run it as (imageusers), and the images that an image section of the config file
names, with where they were pulled from, which shows whether the section applies (ServiceImages).

A project file is untrusted, so dockscreen cannot just assume that a service without `user:` runs as root
or as its image says; a service whose user the command line chose (`run -u`) runs as that one, so no one
asks its image. The rest is the policy's and decisions': the policy pins the users it accepts in the
generated config only, with the image it checked, so that neither the files the project owns nor `harden`
output turn off the project's updates; a service that does not start, or whose user the command line
chose, gets the default user in case something starts it without that user.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.host.docker import DockerError
from dockscreen.model.image import Image, ImageInspection
from dockscreen.model.project import Project, ServiceImages
from dockscreen.policy import sections
from dockscreen.policy.finding import Finding, failure_of
from dockscreen.screen import imageusers
from dockscreen.screen.screener import Screener


def prepare(command: Sequence[str], project: Project, args: Sequence[str], screener: Screener,
            chosen_services: frozenset[str] = frozenset()) -> tuple[ServiceImages | None, list[Finding]]:
    """Finds out what screening needs to know about project's services, for the policy to decide on
    (Screener.decide): pulls and builds the images of the services that start as `up` would, and looks at
    those of the services that set no user.

    Returns (what was found of the images, the failures to acquire them), None for the first if one failed.

    Parameters:
    - command: the compose command line (up to the subcommand) on the project's definition, as it will run
    - project: the hardened project
    - args: the arguments after the subcommand, which name services and may carry --build or --pull
    - screener: the Screener to pull, build, decide and run with
    - chosen_services: services whose user the command line chooses (`run -u`); their images are not looked at
    """
    config = project.definition
    try:
        started_services = _services_to_run(command, config, args, screener)
        services_to_look_at = (started_services - chosen_services) & project.services_without_user
        inspections, failures = imageusers.find(command, project, started_services, services_to_look_at,
                                                args, screener)
    except DockerError as e:
        return None, [failure_of(e)]
    if failures:
        return None, failures
    inspected_images = {name: inspection.image for name, inspection in inspections.items()
                        if isinstance(inspection, ImageInspection)}
    section_images = {**_find_section_images(config, screener), **inspected_images}
    return ServiceImages(section_images, inspections), []


def _find_section_images(config: dict[str, Any], screener: Screener) -> dict[str, Image]:
    """Finds the images of the services that an image section of the config file names, with where they
    were pulled from, which shows whether the section applies; the checks before the images were there
    trusted the name alone.

    A section trusts a repository's maintainer, but a name proves nothing: a project can build or tag an
    image of its own as `mariadb` and so borrow the user, mount dirs or security options configured for
    the real one. Only a repo digest for the repository, recorded when docker pulled the image from there,
    shows its origin (sections.section_for).

    Returns {service: image} for those that are here.
    """
    settings = screener.runtime.settings
    section_images = {}
    for name, service in (config.get("services") or {}).items():
        image, is_built = imageusers.image_name(config, name, service), "build" in service
        if sections.repository_for_name(settings, image, is_built) is None:
            continue
        try:
            image_info = screener.docker.inspect_image(image)
        except DockerError:
            continue  # not there: the section does not apply, and the final check says what that means
        section_images[name] = Image(image, image_info.get("Id"), is_built,
                                     tuple(image_info.get("RepoDigests") or ()))
    return section_images


def _services_to_run(command: Sequence[str], config: dict[str, Any], args: Sequence[str],
                     screener: Screener) -> frozenset[str]:
    """Determines the services the command starts: those in the active profiles, plus any named in args.

    Compose starts a service in an inactive profile when the command names it (`compose run debug`), so
    it counts as started and the policy decides its image like the others'; leaving it out would let it
    run as its image says.

    Raises DockerError if compose cannot list them.
    """
    result = screener.docker.capture([*command, "config", "--services"])
    if result.returncode != 0:
        raise DockerError("docker compose config --services failed")
    services = config.get("services") or {}
    return frozenset(set(result.stdout.split()) | {a for a in args if a in services})
