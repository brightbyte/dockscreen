"""The images of services that set no `user`: get them as compose would, then decide as `docker run` does.

A project file is hostile, so a service without `user:` cannot just be assumed to run as root or as
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

import copy
import json
from typing import NamedTuple

from dockscreen import argscan, ids, imagedecision, images, messages, policy, verdict
from dockscreen.dockerclient import DockerError


class ImageError(Exception):
    pass


class Decision(NamedTuple):
    image: str
    assessment: imagedecision.Assessment
    image_id: str | None = None  # what the image name was when it was looked at
    built: bool = False          # the service builds the image, so no image section applies


class Prepared(NamedTuple):
    """What prepare found for config, and decided with ctx (an imagedecision.Context)."""
    config: dict
    ctx: imagedecision.Context
    to_run: frozenset
    decisions: dict   # service -> Decision, for the started services that set no user
    problems: list
    failed: bool = False  # some problems are failures to get or look at an image, not refusals
    verified: dict | None = None  # service -> the repository whose image section its image proved

    def finalize(self):
        """(config to run, services whose user dockscreen set from the vetted image). config is left alone."""
        settings = self.ctx.settings
        final = copy.deepcopy(self.config)
        vetted = set()
        for name, service in final["services"].items():
            if service.get("user"):
                continue
            decision = self.decisions.get(name)
            if decision is None:  # not started by this command
                # an allowed id: the policy accepts it
                service["user"] = ids.format_user(settings.default_user)
                give_default_home(service, settings.default_user, settings.default_home)
                continue
            if not decision.assessment.pins_user:
                continue
            # pinned as numbers: the runtime reads neither passwd nor group for `uid:gid`, so it cannot
            # resolve the image's user to anything but what was checked
            service["user"] = ids.format_user(decision.assessment.user)
            if decision.assessment.kind is imagedecision.Kind.FALLBACK:
                give_default_home(service, decision.assessment.user, decision.assessment.home)
            else:
                vetted.add(name)  # ... which needs no vetting
            service["pull_policy"] = "never"  # the image that was checked is the one that runs
            if decision.image_id and "build" not in service:
                service["image"] = decision.image_id  # ... even if the name is moved to another image
        return final, frozenset(vetted)

    def describe(self):
        """One line per service without a user: what dockscreen will do about it."""
        lines = []
        for name in sorted(unset_user_services(self.config)):
            decision = self.decisions.get(name)
            if decision is None:
                default = ids.format_user(self.ctx.settings.default_user)
                text = (f"service {name}: no user set and not started by default; dockscreen runs it as the "
                        f"default user ({default}) if it is started")
                lines.append(messages.notable_change(text, USER_HELP))
                continue
            assessment, dot = decision.assessment, verdict.dot(decision.assessment)
            if assessment.kind in (imagedecision.Kind.OK, imagedecision.Kind.CONFIGURED):
                runs_as = imagedecision.runs_as(assessment, self.ctx.local)
                text = f"service {name}: no user set; image {decision.image} {runs_as}"
                lines.append(messages.Marked(dot, text))
            elif assessment.kind is imagedecision.Kind.FALLBACK:
                instead = imagedecision.instead_of_root(assessment)
                lines.append(messages.notable_change(f"service {name}: no user set; {instead}", USER_HELP))
            if assessment.note:
                lines.append(messages.Marked(messages.WARN, f"service {name}: note: {assessment.note}"))
        return [*lines, *self.pin_notices()]

    def notices(self):
        """What a run is about to do that the project did not ask for, as marked lines."""
        return [
            messages.notable_change(
                f"service {name}: {imagedecision.instead_of_root(d.assessment)}", USER_HELP)
            for name, d in self.decisions.items() if d.assessment.kind is imagedecision.Kind.FALLBACK
        ] + self.pin_notices()

    def pin_notices(self):
        """One line for the services whose checked user and image are fixed in the generated file, if any."""
        names = [name for name, d in self.decisions.items() if d.assessment.pins_user]
        if not names:
            return []
        return [messages.routine_change(
            f"services {', '.join(names)}: user, image id and pull_policy: never fixed to what was checked, "
            "in the generated file only")]


def unset_user_services(config):
    """The names of the services in config that set no user."""
    return frozenset(n for n, s in (config.get("services") or {}).items() if not (s or {}).get("user"))


def image_name(config, name, service):
    """The image compose uses: the service's own, or <project>-<service> for one that is built."""
    return service.get("image") or f"{config.get('name', '')}-{name}"


def prepare(command, config, args, ctx, chosen=frozenset()):
    """Acquire the images of the services that will start and decide about those without a user.

    command: the compose command line (up to the subcommand) on the config to run.
    args: the arguments after the subcommand, which name services and may carry --build or --pull.
    ctx: the imagedecision.Context to pull, build, decide and run with.
    chosen: services whose user the command line chooses (`run -u`); their images are not decided.
    """
    try:
        verify_round_trip(command, config, ctx)
        to_run = services_to_run(command, config, args, ctx)
        failures = acquire(command, config, to_run, args, ctx)
    except ImageError as e:
        return Prepared(config, ctx, frozenset(), {}, [str(e)], failed=True)
    if failures:
        return Prepared(config, ctx, to_run, {}, failures, failed=True)

    decisions = decide(config, to_run - chosen, ctx)
    verified = verify_sections(config, ctx)
    config_file = ctx.runtime.config_file
    problems = [decision_problem(name, d, config_file)
                for name, d in decisions.items() if d.assessment.refused]
    failed = any(d.assessment.failed for d in decisions.values())
    return Prepared(config, ctx, to_run, decisions, problems, failed=failed, verified=verified)


def verify_sections(config, ctx):
    """{service: repository} for the services whose image the config file has a section for, and that
    was proven pulled from there. The checks before the images were there trusted the name alone."""
    settings = ctx.runtime.settings
    verified = {}
    for name, service in (config.get("services") or {}).items():
        image, built = image_name(config, name, service), "build" in service
        if images.name_matches(settings, image, built) is None:
            continue
        try:
            digests = ctx.docker.inspect_image(image).get("RepoDigests")
        except DockerError:
            continue  # not there: the section does not apply, and the final check says what that means
        if repository := images.section_for(settings, image, digests, built).repository:
            verified[name] = repository
    return verified


def decision_problem(name, decision, config_file=None):
    """Why the service must not run, for a decision that refused or failed.

    config_file: named in the hint for an image that is pulled, whose repository can be given a user.
    """
    text = f"service {name}: image {decision.image}: {'; '.join(decision.assessment.problems)}"
    if decision.assessment.failed:
        return text
    hint = images.section_hint(decision.image, config_file, decision.built) if config_file else None
    return messages.Reason(text, "set user: to choose one" + (f", or {hint}" if hint else ""))


def verify_round_trip(command, config, ctx):
    """Refuse unless compose, given the generated file, resolves it to exactly the config we checked.

    Compose interpolates the files it reads; a value that comes back different would run
    differently from what the policy saw. Done before anything is pulled or built.
    """
    result = ctx.docker.capture(
        [*command, "--profile", "*", "config", "--format", "json", "--no-env-resolution"])
    try:
        resolved = json.loads(result.stdout) if result.returncode == 0 else None
    except ValueError:
        resolved = None
    if resolved is None:
        raise ImageError("docker compose could not read back the config that was checked")
    where = first_difference(config, resolved)
    if where:
        raise ImageError(f"docker compose reads the checked config differently at {where}; not running it")


def first_difference(expected, actual, path="config"):
    """Where two JSON values first differ (a path), or None."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual), key=str):
            if key not in expected or key not in actual:
                return f"{path}.{key}"
            if where := first_difference(expected[key], actual[key], f"{path}.{key}"):
                return where
        return None
    if isinstance(expected, list) and isinstance(actual, list) and len(expected) == len(actual):
        for i, (e, a) in enumerate(zip(expected, actual)):
            if where := first_difference(e, a, f"{path}[{i}]"):
                return where
        return None
    return None if expected == actual and type(expected) is type(actual) else path


def services_to_run(command, config, args, ctx):
    """Services in the active profiles, plus any named on the command line."""
    result = ctx.docker.capture([*command, "config", "--services"])
    if result.returncode != 0:
        raise ImageError("docker compose config --services failed")
    services = config.get("services") or {}
    return frozenset(set(result.stdout.split()) | {a for a in args if a in services})


def acquire(command, config, to_run, args, ctx):
    """Pull and build what `up` would, by the project's policy. Returns a list of failures."""
    pull, build = [], []
    override = argscan.option_value(args, "--pull")
    for name in sorted(to_run):
        service = config["services"][name]
        image = image_name(config, name, service)
        present = image_exists(ctx.docker, image)
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


def image_exists(docker, image):
    """Whether docker has image locally."""
    try:
        docker.inspect_image(image)
    except DockerError:
        return False
    return True


def decide(config, to_run, ctx):
    """For each started service without a user: what its image would be allowed to do."""
    decisions = {}
    for name in sorted(to_run & unset_user_services(config)):
        service = config["services"][name]
        image = image_name(config, name, service)
        platform = ["--platform", service["platform"]] if service.get("platform") else []
        _, container = ctx.docker.create(["--pull=never", *platform, "--", image])
        image_id = None
        if container is None:
            assessment = imagedecision.Assessment(
                imagedecision.Kind.FAILED, ["the image is not available locally"])
        else:
            try:
                info = ctx.docker.inspect_container(container)
                image_id = info.get("Image")
                assessment = imagedecision.assess(ctx, container, info, explicit=False,
                                         mounts=policy.has_host_mounts(service, config.get("volumes")),
                                         reference=image,
                                         built="build" in service)
            except (DockerError, ValueError, KeyError) as e:
                assessment = imagedecision.Assessment(imagedecision.Kind.FAILED, [str(e)])
            finally:
                ctx.docker.remove(container)
        decisions[name] = Decision(image, assessment, image_id, built="build" in service)
    return decisions


def give_default_home(service, user, home):
    """HOME for the default user that replaces root, unless the service sets one."""
    if home := imagedecision.default_home(user, home):
        service["environment"] = {"HOME": home, **(service.get("environment") or {})}


USER_HELP = ("set user: on the service to choose one; the default user may not be able to use files and "
             "volumes set up for root")
