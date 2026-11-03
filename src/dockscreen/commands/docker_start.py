"""This module implements `docker start` and `docker restart`, with the same check as `run`, on containers
that already exist.

An existing container cannot be rewritten, so one whose user dockscreen would replace (by the default
user or a configured one) is refused like one whose user is not accepted, unless it already runs as
that user.

Docker does not record where a container was created, and its labels, which its image can set, prove
nothing. So it is judged without a directory: no project section of the config file applies, and only
the configured mount_dirs allow bind mounts.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.host.dockerclient import DockerError, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.container import Container
from dockscreen.model.origin import STRICT, Origin
from dockscreen.screen import findings, verdict
from dockscreen.screen.assessment import Assessment
from dockscreen.screen.findings import Finding, Report
from dockscreen.screen.screener import Screener
from dockscreen.screen.verdict import explain
from dockscreen.util import commandline, ids, messages

# Options of `docker start` and `restart` that take a value.
VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


def gate(global_args: Sequence[str], lead: list[str], args: list[str], runtime: Runtime,
         allow_me: bool = False, strict: bool = False) -> int:
    """Runs `lead args` if every container it names passes check; returns 1 if one does not, otherwise docker
    replaces this process.

    Parameters:
    - global_args: docker's options before the subcommand
    - lead: the docker command line up to and including the subcommand (`docker start` or `restart`), with
      docker's options
    - args: the subcommand's arguments
    - runtime: the Runtime of the command
    - allow_me: --allow-me was given, so the caller's own ids are allowed
    - strict: --strict-screen was given (check)
    """
    if not verdict.screened(Report.of(check(global_args, args, runtime, allow_me, strict))):
        return 1
    runtime.docker.exec([*lead, *args])


def check(global_args: Sequence[str], args: Sequence[str], runtime: Runtime, allow_me: bool = False,
          strict: bool = False) -> list[Finding]:
    """Returns the refusals that forbid starting the containers named in `docker global_args start args`
    (or `restart`).

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the default user
    or a configured one) is refused like one whose user is not accepted, unless it already runs as that user.

    Parameters:
    - global_args: docker's options before the subcommand
    - args: the subcommand's arguments
    - runtime: the Runtime of the command
    - allow_me: --allow-me was given, so the caller's own ids are allowed
    - strict: --strict-screen was given, so what the command line that created a container asked for is judged
      as a project's would be, and refused (Policy.check_container)
    """
    screener = Screener(runtime, allow_me)
    if is_remote(global_args, runtime.docker):
        return screener.policy(None).check_daemon(True)
    problems: list[Finding] = []
    for ref in commandline.positionals(args, VALUE_LONG, VALUE_SHORT):
        try:
            info = screener.docker.inspect_container(ref)
            assessment = screener.assess(None, info["Id"], info)
            replaces_image_user = assessment.pins_user and assessment.origin is not Origin.IMAGE
            if replaces_image_user and not _runs_as_pinned_user(info, assessment):
                user = ids.format_user(assessment.pinned_user)
                problems.append(Finding(
                    f"cannot change the user of an existing container; it would run as the "
                    f"image's user, not as {user}", subject=ref, help=f"recreate it with --user {user}"))
            else:
                explained = explain(assessment, runtime.config_file)
                problems += [Finding(p.text, subject=ref, help=p.help) for p in explained]
            if strict:
                chosen = assessment.origin is Origin.COMMAND_LINE
                user_origin = Origin.COMMAND_LINE if chosen else Origin.IMAGE
                strict_policy = screener.policy(None, assessment.section, STRICT)
                found = strict_policy.check_container(Container(info, None, user_origin))
                problems += findings.about(found, ref)
        except (DockerError, ValueError, KeyError) as e:
            problems.append(Finding(messages.with_output(e), subject=ref))
    return problems


def _runs_as_pinned_user(info: dict[str, Any], assessment: Assessment) -> bool:
    """Tells whether the container was created with the numeric user dockscreen would have chosen."""
    return ids.parse_user(info["Config"].get("User") or "") == assessment.user
