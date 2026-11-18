"""This module provides functions for screening a container. The function create makes a container as
`docker run` would, and the policy decides its user. The function check_existing judges a container that
exists already. The function command_line_findings finds the requests of the command line that a project
or an image may not make.

The function create inspects the container that docker created, and has the policy judge it. It leaves the
container for
the calling code to start or remove, since only the calling code knows what comes next: running it,
creating it again with the decided user, or reporting on it.

Containers need screening because `docker run IMAGE` runs the image as the user it chooses, root by default,
and the image is someone else's. The command line is trusted, but it does not say which user the image
picks, nor the identity the image's passwd and group files give it; only the image does. So dockscreen has
docker create the container, which lets the daemon read the command line with all its options, and inspects
it before it starts. The policy then judges docker's own container, not dockscreen's reading of a command
line with a hundred options. dockscreen still reads the command line far enough to find the image and the
user options, so it checks that reading against the container (_verify_split). A misreading must not make
the policy judge another image than the one that runs, or miss a --user.

Anyone may have created an existing container (check_existing), perhaps with plain docker or a project's
script. `docker start` would run it without any of this, and dockscreen cannot rewrite it, so the policy
judges it as it is. The audit command points out the command line's requests (command_line_findings) because
people copy commands from READMEs too: the user may trust a command line they did not write.
"""

from typing import Any

from dockscreen.host.docker import DockerError
from dockscreen.model.container import Container
from dockscreen.model.image import Image
from dockscreen.model.origin import STRICT_ORIGINS, Origin
from dockscreen.policy import finding
from dockscreen.policy.commandlinepatch import CommandLinePatch
from dockscreen.policy.finding import Finding, ReportEntry
from dockscreen.policy.userdecision import UserDecision
from dockscreen.policy.userdecisionview import explain_existing
from dockscreen.screen import runargs
from dockscreen.screen.screener import Screener
from dockscreen.util import ids, messages


def create(screener: Screener, run_args: runargs.RunArgs[str], changes: CommandLinePatch,
           first_decision: UserDecision | None = None) -> tuple[int, tuple[Container, UserDecision] | None]:
    """Creates the container as `docker run` would. Returns (exit status, (container, decision of its user)),
    or (exit status, None) if docker could not create it; docker has then said why.

    The container is left for the calling code to remove.

    Parameters:
    - screener: the Screener of the command
    - run_args: the `docker run` command line, as parsed
    - changes: what goes before the command line's own arguments: the defaults, and the user decided
    - first_decision: the decision about a first creation, whose user changes pins. The policy then does not
      assess the container again; dockscreen only checks that it is what the command line asked for. Its
      user has the same origin as the user of first_decision.
    """
    code, container_id = screener.docker.create(changes.apply_to(run_args.create_args))
    if container_id is None:
        return code, None
    here = screener.runtime.cwd
    container, image = Container.placeholder(container_id, here), Image(run_args.image)
    try:
        info = screener.docker.inspect_container(container_id)
        container = Container(info, here, _user_origin(run_args, first_decision))
        problems = _verify_split(container.info, run_args)  # a misread command line may hide a --user
        if problems:
            decision = UserDecision(None, image, (), tuple(problems))
        else:
            decision = first_decision or screener.assess(screener.runtime.cwd, container.id, container.info,
                                                         container.user_origin, reference=run_args.image)
    except (DockerError, ValueError, KeyError) as e:
        decision = UserDecision.failure(image, messages.with_output(e))
    return code, (container, decision)


def _user_origin(run_args: runargs.RunArgs[str], first_decision: UserDecision | None) -> Origin:
    """Returns the origin of the container's user. For a container that create made again with
    first_decision, it is the origin of that decision's user. Otherwise it is the command line, if the
    command line gives a user, and else the image.
    """
    if first_decision is not None and first_decision.origin is not None:
        return first_decision.origin
    return Origin.COMMAND_LINE if run_args.users.is_user_chosen else Origin.IMAGE


def _verify_split(info: dict[str, Any], run_args: runargs.RunArgs[str]) -> list[Finding]:
    """Checks that our reading of the command line matches the container the daemon created.

    The module runargs reads the command line only far enough to find the image and the command, and it
    does not know every option that docker has. An option that runargs does not know to take a value would
    shift its reading: runargs would take the option's value for the image, or the image for part of the
    command. The user options are
    found by the same reading. This refuses a container whose image or command differs from that reading,
    since the image the policy decided on and the --user found may then not be the ones that run.

    Returns the problem if the reading and the container differ, else an empty list.
    """
    config = info["Config"]
    misread_image = config.get("Image") != run_args.image
    # without a command of its own the container has the image's Cmd, which says nothing about our reading
    misread_command = run_args.command and (config.get("Cmd") or []) != list(run_args.command)
    if misread_image or misread_command:
        return [Finding("could not reliably tell the image from the command line",
                        help="use the real docker for this one")]
    return []


def command_line_findings(screener: Screener, container: Container, decision: UserDecision,
                          trust: frozenset[Origin]) -> list[ReportEntry]:
    """Returns the requests of the command line, as the container it created shows them, that a project or an
    image may not make (Policy.check_container). Each is a refusal, or a warning where trust includes the
    command line.

    Empty if the container could not be inspected.

    Parameters:
    - screener: the Screener of the command
    - container: the container, as the function create returns it
    - decision: the decision about its user, as the function create returns it
    - trust: the origins the policy trusts: TRUSTED_ORIGINS, or STRICT_ORIGINS for --strict-screen
    """
    if not container.is_inspected:
        return []
    return screener.policy(screener.runtime.cwd, decision.section, trust).check_container(container)


def check_existing(screener: Screener, ref: str, is_strict: bool) -> list[ReportEntry]:
    """Returns the refusals that forbid starting the existing container ref, each about ref.

    dockscreen cannot rewrite an existing container. So if dockscreen would replace the container's user (by
    the default user or a configured one), this refuses the container, just as it refuses a container whose
    user the policy does not accept. The exception is a container that already runs as the replacement user.
    Docker does not record where it created a container, so the policy judges it without a directory.

    Parameters:
    - screener: the Screener of the command
    - ref: the name or id of the container
    - is_strict: whether the policy judges the requests of the command line that created the container as
      it would judge a project's, and refuses them (Policy.check_container)
    """
    problems: list[ReportEntry] = []
    try:
        info = screener.docker.inspect_container(ref)
        decision = screener.assess(None, info["Id"], info)
        replaces_image_user = decision.pins_user and decision.origin is not Origin.IMAGE
        if replaces_image_user and not _runs_as_pinned_user(info, decision):
            user_spec = ids.format_user(decision.pinned_user)
            problems.append(Finding(
                f"cannot change the user of an existing container; it would run as the "
                f"image's user, not as {user_spec}", subject=ref,
                help=f"recreate it with --user {user_spec}"))
        else:
            problems += finding.with_subject(explain_existing(decision, screener.runtime.config_file), ref)
        if is_strict:
            is_chosen_on_command_line = decision.origin is Origin.COMMAND_LINE
            user_origin = Origin.COMMAND_LINE if is_chosen_on_command_line else Origin.IMAGE
            strict_policy = screener.policy(None, decision.section, STRICT_ORIGINS)
            container = Container(info, None, user_origin)
            problems += finding.with_subject(strict_policy.check_container(container), ref)
    except (DockerError, ValueError, KeyError) as e:
        problems.append(Finding(messages.with_output(e), subject=ref))
    return problems


def _runs_as_pinned_user(info: dict[str, Any], decision: UserDecision) -> bool:
    """Tells whether the container was created with the numeric user dockscreen would have chosen."""
    return ids.parse_user(info["Config"].get("User") or "") == decision.user
