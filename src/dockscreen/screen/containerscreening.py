"""This module provides functions for screening a container: one created as `docker run` would create it,
whose user the policy then decides (create), one that exists already (check_existing), and what the command
line that made either asks for that a project or an image may not (command_line_findings).

create inspects the container docker created and has the policy judge it, and leaves it for the calling code
to start or remove: only the calling code knows whether it is to run, be created again with the user decided,
or be reported on.

Containers need screening because `docker run IMAGE` runs the image as the user it chooses, root by default,
and the image is someone else's. The command line is trusted, but it does not say which user the image
picks, nor the identity the image's passwd and group files give it; only the image does. So the container is
created, which lets the daemon read the command line with all its options, and inspected before it starts:
the judged container is docker's own, not dockscreen's reading of a command line with a hundred options.
dockscreen still reads the command line far enough to find the image and the user options, so it checks
that reading against the container (_verify_split): a misreading must not judge another image than the
one that runs, or miss a --user.

Anyone may have created an existing container (check_existing), perhaps with plain docker or a project's
script, and `docker start` would run it without any of this; dockscreen cannot rewrite it, so the policy
judges it as it is. Audit points out the command line's requests (command_line_findings) because people
copy commands from READMEs too: the user may trust a command line they did not write.
"""

from typing import Any

from dockscreen.host.docker import DockerError
from dockscreen.model.container import Container
from dockscreen.model.image import Image
from dockscreen.model.origin import STRICT, Origin
from dockscreen.policy import finding
from dockscreen.policy.commandlinepatch import CommandLinePatch
from dockscreen.policy.finding import Finding, Reportable
from dockscreen.policy.userdecision import UserDecision
from dockscreen.policy.userdecisionview import explain_existing
from dockscreen.screen import runargs
from dockscreen.screen.screener import Screener
from dockscreen.util import ids, messages


def create(screener: Screener, parsed: runargs.RunArgs[str], changes: CommandLinePatch,
           decided: UserDecision | None = None) -> tuple[int, tuple[Container, UserDecision] | None]:
    """Creates the container as `docker run` would and returns (exit status, (container, decision of its
    user)), or (exit status, None) if docker could not create it; it said why.

    The container is left for the calling code to remove.

    Parameters:
    - screener: the Screener of the command
    - parsed: the `docker run` command line, as parsed
    - changes: what goes before the command line's own arguments: the defaults, and the user decided
    - decided: the decision of a first creation, whose user changes pins; the container is then not assessed
      again, only checked to be what the command line asked for, and its user comes from where the decided one
      does
    """
    code, created = screener.docker.create(changes.applied_to(parsed.create_args))
    if created is None:
        return code, None
    here = screener.runtime.cwd
    container, image = Container.uninspected(created, here), Image(parsed.image)
    try:
        container = Container(screener.docker.inspect_container(created), here, _user_origin(parsed, decided))
        problems = _verify_split(container.info, parsed)  # a misread command line may hide a --user
        if problems:
            decision = UserDecision(None, image, (), tuple(problems))
        else:
            decision = decided or screener.assess(screener.runtime.cwd, container.id, container.info,
                                                    container.user_origin, reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        decision = UserDecision.failure(image, messages.with_output(e))
    return code, (container, decision)


def _user_origin(parsed: runargs.RunArgs[str], decided: UserDecision | None) -> Origin:
    """Returns where the user of the container comes from: where the decided one does, for a container
    re-created with it (create), else the command line if it gives one, else the image.
    """
    if decided is not None and decided.origin is not None:
        return decided.origin
    return Origin.COMMAND_LINE if parsed.users.chosen else Origin.IMAGE


def _verify_split(info: dict[str, Any], parsed: runargs.RunArgs[str]) -> list[Finding]:
    """Checks that our reading of the command line matches the container the daemon created.

    runargs reads the command line only far enough to find the image and the command, and does not know
    every option docker has: an option it does not know to take a value would shift its reading, so that
    it takes the option's value for the image, or the image for part of the command. The user options are
    found by the same reading. This refuses a container whose image or command differs from that reading,
    since the image the policy decided on and the --user found may then not be the ones that run.

    Returns the problem if it does not, else an empty list.
    """
    config = info["Config"]
    misread_image = config.get("Image") != parsed.image
    # without a command of its own the container has the image's Cmd, which says nothing about our reading
    misread_command = parsed.command and (config.get("Cmd") or []) != list(parsed.command)
    if misread_image or misread_command:
        return [Finding("could not reliably tell the image from the command line",
                        help="use the real docker for this one")]
    return []


def command_line_findings(screener: Screener, container: Container, decision: UserDecision,
                          trust: frozenset[Origin]) -> list[Reportable]:
    """Returns what the command line asks for, in the container it created, that a project or an image may not
    have: refused, or a warning where trust trusts the command line (Policy.check_container).

    Empty if the container could not be inspected.

    Parameters:
    - screener: the Screener of the command
    - container: the container, as create gives it
    - decision: the decision of its user, as create gives it
    - trust: the origins the policy trusts: TRUSTED, or STRICT for --strict-screen
    """
    if not container.inspected:
        return []
    return screener.policy(screener.runtime.cwd, decision.section, trust).check_container(container)


def check_existing(screener: Screener, ref: str, strict: bool) -> list[Reportable]:
    """Returns the refusals that forbid starting the existing container ref, each about ref.

    dockscreen cannot rewrite an existing container, so this refuses one whose user dockscreen would replace
    (by the default user or a configured one) like one whose user the policy does not accept, unless it
    already runs as that user. Docker does not record where it created a container, so the policy judges it
    without a directory.

    Parameters:
    - screener: the Screener of the command
    - ref: the name or id of the container
    - strict: whether what the command line that created it asked for is judged as a project's would be, and
      refused (Policy.check_container)
    """
    problems: list[Reportable] = []
    try:
        info = screener.docker.inspect_container(ref)
        decision = screener.assess(None, info["Id"], info)
        replaces_image_user = decision.pins_user and decision.origin is not Origin.IMAGE
        if replaces_image_user and not _runs_as_pinned_user(info, decision):
            user = ids.format_user(decision.pinned_user)
            problems.append(Finding(
                f"cannot change the user of an existing container; it would run as the "
                f"image's user, not as {user}", subject=ref, help=f"recreate it with --user {user}"))
        else:
            problems += finding.about(explain_existing(decision, screener.runtime.config_file), ref)
        if strict:
            chosen = decision.origin is Origin.COMMAND_LINE
            user_origin = Origin.COMMAND_LINE if chosen else Origin.IMAGE
            strict_policy = screener.policy(None, decision.section, STRICT)
            problems += finding.about(strict_policy.check_container(Container(info, None, user_origin)), ref)
    except (DockerError, ValueError, KeyError) as e:
        problems.append(Finding(messages.with_output(e), subject=ref))
    return problems


def _runs_as_pinned_user(info: dict[str, Any], decision: UserDecision) -> bool:
    """Tells whether the container was created with the numeric user dockscreen would have chosen."""
    return ids.parse_user(info["Config"].get("User") or "") == decision.user
