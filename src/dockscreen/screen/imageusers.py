"""This module provides functions for finding out which user the images of compose services would run them
as, by whatever it takes: dockscreen pulls or builds the images as compose would, and then looks at them,
so that the policy can decide the user to use by the rule `docker run` uses (rules.userrules). Which
services' images to look at is the calling code's to say (serviceinfo).

An image is untrusted, so dockscreen cannot take its user from its name or its config alone. It first
acquires the images of the services that start, following the project's own pull policy so that automatic
updates keep happening (pull, or build if the service builds it from a Dockerfile); they are then the
images that run, since the policy pins them. It then looks at each image asked about through a container
that docker creates from it and no one starts (Screener.look).
"""

from collections.abc import Collection, Sequence
from typing import Any

from dockscreen.host.docker import Docker, DockerError
from dockscreen.model.image import Image, ImageInspection, UnseenImage
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.policy import finding
from dockscreen.policy.finding import Finding
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, messages


def find(command: Sequence[str], project: Project, started_services: Collection[str],
         services_to_look_at: Collection[str],
         args: Sequence[str], screener: Screener) -> tuple[dict[str, ImageInspection | UnseenImage],
                                                           list[Finding]]:
    """Gets the images of the services in started_services as `up` would, and looks at those of the services
    in services_to_look_at, as far as the policy needs to decide what they may run as.

    Returns (what was seen of each image looked at, by service, UnseenImage for one that could not be looked
    at; the failures to get the images), with nothing looked at if getting one failed.

    Parameters:
    - command: the compose command line (up to the subcommand) on the project's definition, as it will run
    - project: the project the services are in
    - started_services: the services that start, whose images are got
    - services_to_look_at: the services whose images are looked at; each must be in started_services
    - args: the arguments after the subcommand, which may carry --build or --pull
    - screener: the Screener to pull, build and look with
    """
    failures = _acquire(command, project.definition, started_services, args, screener.docker)
    if failures:
        return {}, finding.failures(failures)
    return {name: _look(project, name, screener) for name in sorted(services_to_look_at)}, []


def image_name(config: dict[str, Any], name: str, service: dict[str, Any]) -> str:
    """Returns the image compose uses for the service called name in config: its own, or <project>-<service>
    if it is built.

    Parameters:
    - config: the project's definition
    - name: the service's name
    - service: the service's keys
    """
    return service.get("image") or f"{config.get('name', '')}-{name}"


def _acquire(command: Sequence[str], config: dict[str, Any], started_services: Collection[str],
             args: Sequence[str],
             docker: Docker) -> list[str]:
    """Pulls and builds the images of the services in started_services that `up` would, by each service's pull
    policy and args.

    Returns the failures, empty if everything was acquired.
    """
    services_to_pull, services_to_build = [], []
    pull_override = commandline.option_value(args, "--pull")
    for name in sorted(started_services):
        service = config["services"][name]
        image = image_name(config, name, service)
        is_present = _image_exists(docker, image)
        if "build" in service:
            is_build_wanted = service.get("pull_policy") == "build" or "--build" in args or not is_present
            if is_build_wanted and "--no-build" not in args:
                services_to_build.append(name)
            continue
        pull_policy = pull_override or service.get("pull_policy") or "missing"
        if pull_policy == "never":
            continue
        if pull_policy in ("missing", "if_not_present"):
            if not is_present:
                services_to_pull.append(name)
        else:
            # always, and the periodic ones: pulling each run never serves stale images
            services_to_pull.append(name)
    for subcommand, names in (("pull", services_to_pull), ("build", services_to_build)):
        # `--`: the names are the project's; the policy refuses those that start with `-` as well
        if names and docker.run_child([*command, subcommand, "--", *names]) != 0:
            return [f"docker compose {subcommand} {' '.join(names)} failed"]
    return []


def _image_exists(docker: Docker, image: str) -> bool:
    """Tells whether docker has image locally."""
    try:
        docker.inspect_image(image)
    except DockerError:
        return False
    return True


def _look(project: Project, name: str, screener: Screener) -> ImageInspection | UnseenImage:
    """Looks at the image of the service called name, as far as the policy needs to decide what it may run
    as (Screener.look), through a container created from it and removed again; UnseenImage if that fails.
    """
    config = project.definition
    service = config["services"][name]
    image = Image(image_name(config, name, service), is_built="build" in service)
    platform = ["--platform", service["platform"]] if service.get("platform") else []
    # a container that no one starts shows the user docker would run, and docker cp can copy its files out;
    # --pull=never: the image looked at must be the one acquired above, not a newer one pulled in between
    _, container = screener.docker.create(["--pull=never", *platform, "--", image.reference])
    if container is None:
        return UnseenImage(image, "the image is not available locally")
    try:
        container_info = screener.docker.inspect_container(container)
        inspection, _ = screener.look(project.directory, container, container_info, Origin.IMAGE,
                                      has_mounts=project.service(name).reaches_host,
                                      reference=image.reference, is_built=image.is_built)
        return inspection
    except (DockerError, ValueError, KeyError) as e:
        return UnseenImage(image, messages.with_output(e))
    finally:
        screener.docker.remove(container)
