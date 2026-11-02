"""This module decides which user each service of a compose project runs as where the project leaves that to
the image: it gets the images as compose would, and applies the rule `docker run` uses.

A project file is untrusted, so a service without `user:` cannot just be assumed to run as root or as
whatever its image says. The image is acquired first, following the project's own pull policy so that
automatic updates keep happening (pull, or build if it is built from a Dockerfile), and then the same
rule as `docker run` is applied to the identity it would run as (imagedecision.assess):

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

from collections.abc import Mapping, Sequence
from types import MappingProxyType
from typing import Any, NamedTuple

from dockscreen.host import config as configuration
from dockscreen.host.dockerclient import Docker, DockerError
from dockscreen.model.image import Image
from dockscreen.model.mounts import service_reaches_host
from dockscreen.model.origin import Origin
from dockscreen.screen import findings, imagedecision, substitutions, verdict
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.scope import Scope
from dockscreen.screen.substitutions import Group, Substitution
from dockscreen.util import commandline, ids, images, messages


class ImageError(Exception):
    pass


class Prepared(NamedTuple):
    """Project config whose services' images have been fetched and their users decided in a scope (ctx),
    ready to become the config that runs.
    """
    config: dict
    ctx: Scope
    decisions: dict   # service -> imagedecision.Assessment, for the started services that set no user
    report: Report    # refusals, and failures to get or look at an image
    verified: Mapping[str, str] = MappingProxyType({})  # service -> the repository its image proved

    def changes(self) -> list[Substitution]:
        """Returns the substitutions that make config the config to run, by service name: services that start
        and set no user get the decided user, pinned to the image that was checked; those that do not start
        get the default user.
        """
        found = []
        settings = self.ctx.settings
        for name, service in sorted(self.config["services"].items()):
            if service.get("user"):
                continue
            decision = self.decisions.get(name)
            if decision is None:  # not started by this command
                found += _user(name, service, settings.default_user, settings.default_home)
            elif decision.pins_user:
                found += _pinned(name, service, decision)
        return found

    def describe(self) -> list[messages.Marked]:
        """Describes, in one line per service that sets no user, what dockscreen does about it."""
        lines = []
        for name in sorted(unset_user_services(self.config)):
            decision = self.decisions.get(name)
            if decision is None:
                default = ids.format_user(self.ctx.settings.default_user)
                text = (f"service {name}: no user set and not started by default; dockscreen runs it as the "
                        f"default user ({default}) if it is started")
                lines.append(messages.notable_change(text, USER_HELP))
                continue
            accepted = decision.kind in (imagedecision.Kind.IMAGE, imagedecision.Kind.CONFIGURED)
            if accepted and not decision.refused:
                runs_as = imagedecision.runs_as(decision, self.ctx.local)
                text = f"service {name}: no user set; image {decision.image.reference} {runs_as}"
                lines.append(messages.Marked(verdict.dot(decision), text))
            elif decision.kind is imagedecision.Kind.FALLBACK:
                instead = imagedecision.instead_of_root(decision)
                lines.append(messages.notable_change(f"service {name}: no user set; {instead}", USER_HELP))
            for note in decision.notes:
                lines.append(messages.Marked(messages.WARN, f"service {name}: note: {note}"))
        return [*lines, *substitutions.grouped(self.changes())]

    def notices(self) -> list[messages.Marked]:
        """Lists, as marked lines, what a run does that the project did not ask for."""
        return substitutions.describe(self.changes())


def _user(name: str, service: dict[str, Any], user: tuple[int, int], home: str, text: str | None = None,
          group: Group | None = None) -> list[Substitution]:
    """Returns the substitutions that set the service's user, the configured or the default one, reported
    by text if given, and the HOME that comes with the default user (imagedecision.default_home) unless the
    service sets HOME.
    """
    found = [Substitution(name, "user", ids.format_user(user), text, notable=bool(text),
                          help=USER_HELP if text else None, group=group, origin=Origin.CONFIG)]
    if home := imagedecision.default_home(user, home):
        found.append(Substitution(name, "environment", {"HOME": home, **(service.get("environment") or {})}))
    return found


def _pinned(name: str, service: dict[str, Any], assessment: imagedecision.Assessment) -> list[Substitution]:
    """Returns the substitutions that pin a started service to what the assessment of its image checked:
    the user, as numbers, the image by id unless it is built, and pull_policy never.
    """
    # pinned as numbers: the runtime reads neither passwd nor group for `uid:gid`, so it cannot resolve
    # the image's user to anything but what was checked
    if assessment.kind is imagedecision.Kind.FALLBACK:
        found = _user(name, service, assessment.pinned_user, assessment.home,
                      imagedecision.instead_of_root(assessment), PINNED)
    else:  # the image's user, or the one its image section configures
        origin = Origin.IMAGE if assessment.kind is imagedecision.Kind.IMAGE else Origin.CONFIG
        found = [Substitution(name, "user", ids.format_user(assessment.pinned_user), group=PINNED,
                              origin=origin)]
    # the image checked is what runs
    found.append(Substitution(name, "pull_policy", "never", group=PINNED, origin=Origin.DOCKSCREEN))
    if assessment.image.id and "build" not in service:
        # ... even if the name is moved to another image
        found.append(Substitution(name, "image", assessment.image.id, group=PINNED, origin=Origin.DOCKSCREEN))
    return found


PINNED = Group("services {services}: user, image id and pull_policy: never fixed to what was checked, "
               "in the generated file only")


def unset_user_services(config: dict[str, Any]) -> frozenset[str]:
    """Returns the names of the services in config that set no user."""
    return frozenset(n for n, s in (config.get("services") or {}).items() if not (s or {}).get("user"))


def _image_name(config: dict[str, Any], name: str, service: dict[str, Any]) -> str:
    """Returns the image compose uses for a service: its own, or <project>-<service> if it is built."""
    return service.get("image") or f"{config.get('name', '')}-{name}"


def prepare(command: Sequence[str], config: dict[str, Any], args: Sequence[str], ctx: Scope,
            chosen: frozenset[str] = frozenset()) -> Prepared:
    """Acquires the images of the services that start, and decides on those that set no user.

    Pulls and builds as `up` would. Returns a Prepared; its report passes if every image was acquired and
    accepted.

    command: the compose command line (up to the subcommand) on the config to run.
    args: the arguments after the subcommand, which name services and may carry --build or --pull.
    ctx: the Scope to pull, build, decide and run with.
    chosen: services whose user the command line chooses (`run -u`); their images are not decided.
    """
    try:
        to_run = _services_to_run(command, config, args, ctx)
        failures = _acquire(command, config, to_run, args, ctx)
    except ImageError as e:
        return Prepared(config, ctx, {}, Report.failure(str(e)))
    if failures:
        return Prepared(config, ctx, {}, Report.of(findings.failed(failures)))

    decisions = _decide(config, to_run - chosen, ctx)
    verified = _verify_sections(config, ctx)
    config_file = ctx.runtime.config_file
    found = [decision_problem(name, d, config_file) for name, d in decisions.items() if d.refused]
    return Prepared(config, ctx, decisions, Report.of(found), verified)


def _verify_sections(config: dict[str, Any], ctx: Scope) -> dict[str, str]:
    """Determines which services' images were proven pulled from the repository of their image section.

    Returns {service: repository}. The checks before the images were there trusted the name alone.
    """
    settings = ctx.runtime.settings
    verified = {}
    for name, service in (config.get("services") or {}).items():
        image, built = _image_name(config, name, service), "build" in service
        if configuration.name_matches(settings, image, built) is None:
            continue
        try:
            digests = ctx.docker.inspect_image(image).get("RepoDigests")
        except DockerError:
            continue  # not there: the section does not apply, and the final check says what that means
        if repository := configuration.section_for(settings, image, digests, built).repository:
            verified[name] = repository
    return verified


def decision_problem(name: str, assessment: imagedecision.Assessment, config_file: str | None = None
                     ) -> Finding:
    """Returns, as one finding, why the service must not run, for an assessment of its image that refused
    or failed.

    config_file: named in the hint for an image that is pulled, whose repository can be given a user.
    """
    image = assessment.image
    text = f"image {image.reference}: {'; '.join(r.text for r in assessment.reasons)}"
    if assessment.failed:
        return Finding(text, Severity.FAILED, f"service {name}")
    hint = images.section_hint(image.reference, config_file, image.built) if config_file else None
    return Finding(text, Severity.REFUSED, f"service {name}",
                   "set user: to choose one" + (f", or {hint}" if hint else ""))


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


def _decide(config: dict[str, Any], to_run: frozenset[str],
            ctx: Scope) -> dict[str, imagedecision.Assessment]:
    """Decides, for each service in to_run that sets no user, what its image would be allowed to run as.

    Returns {service: Assessment}. An image that cannot be looked at gets a failed assessment.
    """
    decisions = {}
    for name in sorted(to_run & unset_user_services(config)):
        service = config["services"][name]
        image = Image(_image_name(config, name, service), built="build" in service)
        platform = ["--platform", service["platform"]] if service.get("platform") else []
        # a container that is never started shows the user docker would run, and its files can be copied out
        _, container = ctx.docker.create(["--pull=never", *platform, "--", image.reference])
        if container is None:
            decisions[name] = imagedecision.Assessment.failure(image, "the image is not available locally")
            continue
        try:
            info = ctx.docker.inspect_container(container)
            mounts = service_reaches_host(service, config.get("volumes"))
            decisions[name] = imagedecision.assess(ctx, container, info, Origin.IMAGE, mounts=mounts,
                                                   reference=image.reference, built=image.built)
        except (DockerError, ValueError, KeyError) as e:
            failure = messages.with_output(e)
            decisions[name] = imagedecision.Assessment.failure(image, failure)
        finally:
            ctx.docker.remove(container)
    return decisions


USER_HELP = ("set user: on the service to choose one; the default user may not be able to use files and "
             "volumes set up for root")
