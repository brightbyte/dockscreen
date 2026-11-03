"""This module provides functions for finding out which user the images of compose services would run them
as, by whatever it takes: the images are pulled or built as compose would, and then looked at, so that the
policy can decide the user to use by the rule `docker run` uses (rules.image). Which services' images to
look at is the caller's to say (serviceinfo).

An image is untrusted, so what it says about its user cannot be taken from its name or its config alone.
The images of the services that start are acquired first, following the project's own pull policy so that
automatic updates keep happening (pull, or build if it is built from a Dockerfile); they are then the images
that run, since the policy pins them. Each image asked about is then looked at through a container created
from it and never started (Scope.look).
"""

from collections.abc import Collection, Sequence
from typing import Any

from dockscreen.host.dockerclient import Docker, DockerError
from dockscreen.model.image import Image, Inspected, Unseen
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import findings
from dockscreen.screen.findings import Finding
from dockscreen.screen.scope import Scope
from dockscreen.util import commandline, messages


def find(command: Sequence[str], project: Project, started: Collection[str], looked_at: Collection[str],
         args: Sequence[str], ctx: Scope) -> tuple[dict[str, Inspected | Unseen], list[Finding]]:
    """Gets the images of the services in started as `up` would, and looks at those of the services in
    looked_at, as far as the policy needs to decide what they may run as.

    Returns (what was seen of each image looked at, by service, Unseen for one that could not be looked at;
    the failures to get the images), with nothing looked at if getting one failed.
    command: the compose command line (up to the subcommand) on the project's definition, as it will run.
    args: the arguments after the subcommand, which may carry --build or --pull.
    """
    failures = _acquire(command, project.definition, started, args, ctx.docker)
    if failures:
        return {}, findings.failed(failures)
    return {name: _look(project, name, ctx) for name in sorted(looked_at)}, []


def image_name(config: dict[str, Any], name: str, service: dict[str, Any]) -> str:
    """Returns the image compose uses for the service called name in config: its own, or <project>-<service>
    if it is built.
    """
    return service.get("image") or f"{config.get('name', '')}-{name}"


def _acquire(command: Sequence[str], config: dict[str, Any], started: Collection[str], args: Sequence[str],
             docker: Docker) -> list[str]:
    """Pulls and builds the images of the services in started that `up` would, by each service's pull policy
    and args.

    Returns the failures, empty if everything was acquired.
    """
    pull, build = [], []
    override = commandline.option_value(args, "--pull")
    for name in sorted(started):
        service = config["services"][name]
        image = image_name(config, name, service)
        present = _image_exists(docker, image)
        if "build" in service:
            wanted = service.get("pull_policy") == "build" or "--build" in args or not present
            if wanted and "--no-build" not in args:
                build.append(name)
            continue
        policy = override or service.get("pull_policy") or "missing"
        if policy == "never":
            continue
        if policy in ("missing", "if_not_present"):
            if not present:
                pull.append(name)
        else:
            pull.append(name)  # always, and the periodic ones: pulling each run never serves stale images
    for subcommand, names in (("pull", pull), ("build", build)):
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


def _look(project: Project, name: str, ctx: Scope) -> Inspected | Unseen:
    """Looks at the image of the service called name, as far as the policy needs to decide what it may run
    as (Scope.look), through a container created from it and removed again; Unseen if that fails.
    """
    config = project.definition
    service = config["services"][name]
    image = Image(image_name(config, name, service), built="build" in service)
    platform = ["--platform", service["platform"]] if service.get("platform") else []
    # a container that is never started shows the user docker would run, and its files can be copied out
    _, container = ctx.docker.create(["--pull=never", *platform, "--", image.reference])
    if container is None:
        return Unseen(image, "the image is not available locally")
    try:
        info = ctx.docker.inspect_container(container)
        inspected, _ = ctx.look(project.directory, container, info, Origin.IMAGE,
                                mounts=project.service(name).reaches_host, reference=image.reference,
                                built=image.built)
        return inspected
    except (DockerError, ValueError, KeyError) as e:
        return Unseen(image, messages.with_output(e))
    finally:
        ctx.docker.remove(container)
