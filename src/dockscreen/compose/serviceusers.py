"""This module gets the images of a compose project's services as compose would, and looks at those that
decide which user a service runs as, where the project leaves that to the image, so that the policy can
decide by the rule `docker run` uses (rules.image), and what follows from that (decisions).

A project file is untrusted, so a service without `user:` cannot just be assumed to run as root or as
whatever its image says. The image is acquired first, following the project's own pull policy so that
automatic updates keep happening (pull, or build if it is built from a Dockerfile), and then looked at
through a container created from it and never started (Scope.look). The images of the services that an
image section of the config file names are found too, with where they were pulled from, which shows
whether the section applies (Project.found_images).

What follows is the policy's and decisions': what is accepted is pinned in the generated config only,
with the image that was checked, so that neither the files the project owns nor `harden` output turn off
the project's updates; a service that is not started, or whose user the command line chose (`run -u`),
gets the default user in case it does get started without it.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.host import config as configuration
from dockscreen.host.dockerclient import Docker, DockerError
from dockscreen.model.image import Image, Inspected, Unseen
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import findings
from dockscreen.screen.decisions import Decisions
from dockscreen.screen.findings import Finding, failure_of
from dockscreen.screen.scope import Scope
from dockscreen.util import commandline, messages


def _image_name(config: dict[str, Any], name: str, service: dict[str, Any]) -> str:
    """Returns the image compose uses for a service: its own, or <project>-<service> if it is built."""
    return service.get("image") or f"{config.get('name', '')}-{name}"


def prepare(command: Sequence[str], project: Project, args: Sequence[str], ctx: Scope,
            chosen: frozenset[str] = frozenset()) -> Decisions:
    """Acquires the images of the services that start, and looks at those of the services that set no
    user, for the policy to decide on.

    Pulls and builds as `up` would. Returns the Decisions about the project with what was found of its
    images; their report passes if every image was acquired and accepted.

    command: the compose command line (up to the subcommand) on the project's definition, as it will run.
    args: the arguments after the subcommand, which name services and may carry --build or --pull.
    ctx: the Scope to pull, build, decide and run with.
    chosen: services whose user the command line chooses (`run -u`); their images are not decided.
    """
    config = project.definition
    try:
        to_run = _services_to_run(command, config, args, ctx)
        failures = _acquire(command, config, to_run, args, ctx)
    except DockerError as e:
        return decided(project, ctx, (failure_of(e),))
    if failures:
        return decided(project, ctx, tuple(findings.failed(failures)))

    inspected = _inspect(project, to_run - chosen, ctx)
    found = {**_find_section_images(config, ctx),
             **{name: image.image for name, image in inspected.items() if isinstance(image, Inspected)}}
    return decided(project.with_images(found, inspected), ctx)


def decided(project: Project, ctx: Scope, failures: tuple[Finding, ...] = ()) -> Decisions:
    """Returns the Decisions of the policy for project in ctx, with the failures to acquire its images."""
    return Decisions(project, ctx.project_policy(project), ctx.local, failures)


def _find_section_images(config: dict[str, Any], ctx: Scope) -> dict[str, Image]:
    """Finds the images of the services that an image section of the config file names, with where they
    were pulled from, which shows whether the section applies; the checks before the images were there
    trusted the name alone.

    Returns {service: image} for those that are here.
    """
    settings = ctx.runtime.settings
    found = {}
    for name, service in (config.get("services") or {}).items():
        image, built = _image_name(config, name, service), "build" in service
        if configuration.name_matches(settings, image, built) is None:
            continue
        try:
            inspected = ctx.docker.inspect_image(image)
        except DockerError:
            continue  # not there: the section does not apply, and the final check says what that means
        found[name] = Image(image, inspected.get("Id"), built, tuple(inspected.get("RepoDigests") or ()))
    return found


def _services_to_run(command: Sequence[str], config: dict[str, Any], args: Sequence[str],
                     ctx: Scope) -> frozenset[str]:
    """Determines the services the command starts: those in the active profiles, plus any named in args.

    Raises DockerError if compose cannot list them.
    """
    result = ctx.docker.capture([*command, "config", "--services"])
    if result.returncode != 0:
        raise DockerError("docker compose config --services failed")
    services = config.get("services") or {}
    return frozenset(set(result.stdout.split()) | {a for a in args if a in services})


def _acquire(command: Sequence[str], config: dict[str, Any], to_run: frozenset[str], args: Sequence[str],
             ctx: Scope) -> list[str]:
    """Pulls and builds the images of to_run that `up` would, by each service's pull policy and args.

    Returns the failures, empty if everything was acquired.
    """
    pull, build = [], []
    override = commandline.option_value(args, "--pull")
    for name in sorted(to_run):
        service = config["services"][name]
        image = _image_name(config, name, service)
        present = _image_exists(ctx.docker, image)
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
        if names and ctx.docker.run_child([*command, subcommand, "--", *names]) != 0:
            return [f"docker compose {subcommand} {' '.join(names)} failed"]
    return []


def _image_exists(docker: Docker, image: str) -> bool:
    """Tells whether docker has image locally."""
    try:
        docker.inspect_image(image)
    except DockerError:
        return False
    return True


def _inspect(project: Project, to_run: frozenset[str], ctx: Scope) -> dict[str, Inspected | Unseen]:
    """Looks at the image of each service in to_run that sets no user, as far as the policy needs to decide
    what it may run as (Scope.look), through a container created from it and removed again.

    Returns {service: what was found}, Unseen for an image that could not be looked at.
    """
    config = project.definition
    found: dict[str, Inspected | Unseen] = {}
    for name in sorted(to_run & project.services_without_user):
        service = config["services"][name]
        image = Image(_image_name(config, name, service), built="build" in service)
        platform = ["--platform", service["platform"]] if service.get("platform") else []
        # a container that is never started shows the user docker would run, and its files can be copied out
        _, container = ctx.docker.create(["--pull=never", *platform, "--", image.reference])
        if container is None:
            found[name] = Unseen(image, "the image is not available locally")
            continue
        try:
            info = ctx.docker.inspect_container(container)
            mounts = project.service(name).reaches_host
            found[name], _ = ctx.look(project.directory, container, info, Origin.IMAGE,
                                               mounts=mounts, reference=image.reference, built=image.built)
        except (DockerError, ValueError, KeyError) as e:
            found[name] = Unseen(image, messages.with_output(e))
        finally:
            ctx.docker.remove(container)
    return found


