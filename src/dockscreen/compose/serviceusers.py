"""This module gets the images of a compose project's services as compose would, and looks at those that
decide which user a service runs as, where the project leaves that to the image, so that the policy can
decide by the rule `docker run` uses (Policy.assess_images).

A project file is untrusted, so a service without `user:` cannot just be assumed to run as root or as
whatever its image says. The image is acquired first, following the project's own pull policy so that
automatic updates keep happening (pull, or build if it is built from a Dockerfile), and then the same
rule as `docker run` is applied to the identity it would run as (Policy.check_image):

- the config file names a user for the image's repository, and the image was pulled from there:
  that user;
- root: the configured default user instead (nobody unless configured otherwise), with a notice;
- otherwise the image's own user if the id rules accept it, with the service's mounts; refused if not.

Whatever is accepted is pinned in the generated config as `user: "uid:gid"`.

In the generated config only, services that were looked at get `pull_policy: never` and, unless they are
built, `image:` set to the id of the image that was checked, so that compose runs that image and neither
pulls another one nor follows a tag that something else has moved in between. Neither is written to the files
the project owns or to `harden` output, which would silently turn off the project's updates.

A service that is not started by this command and sets no user is run as the default user if it does get
started: a mistake in working out what starts must fail safe. So is a service whose user the command line
chose (`run -u`), which the command line then overrides.
"""

from collections.abc import Sequence
from typing import Any, NamedTuple

from dockscreen.host import config as configuration
from dockscreen.host.dockerclient import Docker, DockerError
from dockscreen.model.image import Image, Inspected, Unseen
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import findings, imagedecision, policy, substitutions, userchanges, verdict
from dockscreen.screen.assessment import Assessment, Kind
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.scope import Scope
from dockscreen.screen.substitutions import Substitution
from dockscreen.screen.userchanges import USER_HELP
from dockscreen.util import commandline, ids, messages


class ImageError(Exception):
    pass


class Prepared(NamedTuple):
    """Project whose services' images were acquired in a scope (ctx), with what was found of them
    (Project.found_images, Project.inspected), and the failures to acquire them.

    What the images decide is the policy's (Policy.assess_images); the rest follows from that.
    """
    project: Project
    ctx: Scope
    failures: tuple[Finding, ...] = ()  # pulling, building or listing the services failed

    @property
    def config(self) -> dict[str, Any]:
        """Returns the project's definition."""
        return self.project.definition

    @property
    def policy(self) -> policy.Policy:
        """Returns the policy for the project, with the image sections its images were shown to have."""
        return self.ctx.project_policy(self.project)

    @property
    def decisions(self) -> dict[str, Assessment]:
        """Returns the decision about each started service that sets no user, by service."""
        return self.policy.assess_images(self.project)

    @property
    def report(self) -> Report:
        """Returns the failures to acquire the images, and the services whose image must not run."""
        return Report.of([*self.failures, *self.policy.check_images(self.project)])

    def changes(self) -> list[Substitution]:
        """Returns the substitutions that make the project the one to run (userchanges.changes)."""
        project_policy = self.policy
        return userchanges.changes(self.project, self.decisions, project_policy.default_user,
                                   project_policy.default_home)

    def describe(self) -> list[messages.Marked]:
        """Describes, in one line per service that sets no user, what dockscreen does about it."""
        lines = []
        for name in sorted(unset_user_services(self.config)):
            decision = self.decisions.get(name)
            if decision is None:
                default = ids.format_user(self.policy.default_user)
                text = (f"service {name}: no user set and not started by default; dockscreen runs it as the "
                        f"default user ({default}) if it is started")
                lines.append(messages.notable_change(text, USER_HELP))
                continue
            accepted = decision.kind in (Kind.IMAGE, Kind.CONFIGURED)
            if accepted and not decision.refused:
                runs_as = imagedecision.runs_as(decision, self.ctx.local)
                text = f"service {name}: no user set; image {decision.image.reference} {runs_as}"
                lines.append(messages.Marked(verdict.dot(decision), text))
            elif decision.kind is Kind.FALLBACK:
                instead = imagedecision.instead_of_root(decision)
                lines.append(messages.notable_change(f"service {name}: no user set; {instead}", USER_HELP))
            for note in decision.notes:
                lines.append(messages.Marked(messages.WARN, f"service {name}: note: {note}"))
        return [*lines, *substitutions.grouped(self.changes())]

    def notices(self) -> list[messages.Marked]:
        """Lists, as marked lines, what a run does that the project did not ask for."""
        return substitutions.describe(self.changes())


def unset_user_services(config: dict[str, Any]) -> frozenset[str]:
    """Returns the names of the services in config that set no user."""
    return frozenset(n for n, s in (config.get("services") or {}).items() if not (s or {}).get("user"))


def _image_name(config: dict[str, Any], name: str, service: dict[str, Any]) -> str:
    """Returns the image compose uses for a service: its own, or <project>-<service> if it is built."""
    return service.get("image") or f"{config.get('name', '')}-{name}"


def prepare(command: Sequence[str], project: Project, args: Sequence[str], ctx: Scope,
            chosen: frozenset[str] = frozenset()) -> Prepared:
    """Acquires the images of the services that start, and decides on those that set no user.

    Pulls and builds as `up` would. Returns a Prepared; its report passes if every image was acquired and
    accepted.

    command: the compose command line (up to the subcommand) on the project's definition, as it will run.
    args: the arguments after the subcommand, which name services and may carry --build or --pull.
    ctx: the Scope to pull, build, decide and run with.
    chosen: services whose user the command line chooses (`run -u`); their images are not decided.
    """
    config = project.definition
    try:
        to_run = _services_to_run(command, config, args, ctx)
        failures = _acquire(command, config, to_run, args, ctx)
    except ImageError as e:
        return Prepared(project, ctx, (Finding(str(e), Severity.FAILED),))
    if failures:
        return Prepared(project, ctx, tuple(findings.failed(failures)))

    inspected = _inspect(project, to_run - chosen, ctx)
    found = {**_find_section_images(config, ctx),
             **{name: image.image for name, image in inspected.items() if isinstance(image, Inspected)}}
    return Prepared(project.with_images(found, inspected), ctx)


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

    Raises ImageError if compose cannot list them.
    """
    result = ctx.docker.capture([*command, "config", "--services"])
    if result.returncode != 0:
        raise ImageError("docker compose config --services failed")
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
    what it may run as (imagedecision.look), through a container created from it and removed again.

    Returns {service: what was found}, Unseen for an image that could not be looked at.
    """
    config = project.definition
    found: dict[str, Inspected | Unseen] = {}
    for name in sorted(to_run & unset_user_services(config)):
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
            found[name], _ = imagedecision.look(ctx, project.directory, container, info, Origin.IMAGE,
                                               mounts=mounts, reference=image.reference, built=image.built)
        except (DockerError, ValueError, KeyError) as e:
            found[name] = Unseen(image, messages.with_output(e))
        finally:
            ctx.docker.remove(container)
    return found


