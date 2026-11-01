"""`docker start` and `docker restart`: the same check as `run`, on containers that already exist.

An existing container cannot be rewritten, so one whose user dockscreen would replace (by the default
user or a configured one) is refused like one whose user is not accepted, unless it already runs as
that user.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.host.dockerclient import REMOTE_MESSAGE, DockerError, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.screen import imagedecision, verdict
from dockscreen.screen.imagedecision import Assessment, assess, explain
from dockscreen.util import commandline, ids, messages

# Options of `docker start` and `restart` that take a value.
VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


def gate(global_args: Sequence[str], lead: list[str], args: list[str], runtime: Runtime,
         allow_me: bool = False) -> int:
    """Runs `lead args` (`docker start` or `restart`, with docker's options) if every container it names
    passes check; returns 1 if one does not, otherwise docker replaces this process.
    """
    if not verdict.screened(check(global_args, args, runtime, allow_me)):
        return 1
    runtime.docker.exec([*lead, *args])


def check(global_args: Sequence[str], args: Sequence[str], runtime: Runtime, allow_me: bool = False
          ) -> list[str]:
    """Returns the problems that forbid starting the containers named in `docker global_args start args`
    (or `restart`).

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the
    default user or a configured one) is refused like one whose user is not accepted, unless it
    already runs as that user.
    """
    if is_remote(global_args, runtime.docker):
        return [REMOTE_MESSAGE]
    ctx = imagedecision.Context.for_runtime(runtime, allow_me)
    problems: list[str] = []
    for ref in commandline.positionals(args, VALUE_LONG, VALUE_SHORT):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            if assessment.replaces_image_user and not _runs_as_pinned_user(info, assessment):
                user = ids.format_user(assessment.pinned_user)
                problems.append(messages.Reason(
                    f"{ref}: cannot change the user of an existing container; it would run as the "
                    f"image's user, not as {user}", f"recreate it with --user {user}"))
            else:
                image = info["Config"].get("Image") or ""
                problems += [messages.Reason(f"{ref}: {p}", messages.help_of(p))
                             for p in explain(ctx, assessment, image)]
        except (DockerError, ValueError, KeyError) as e:
            problems.append(f"{ref}: {messages.with_output(messages.reason_of(e))}")
    return problems


def _runs_as_pinned_user(info: dict[str, Any], assessment: Assessment) -> bool:
    """Tells whether the container was created with the numeric user dockscreen would have chosen."""
    return ids.parse_user(info["Config"].get("User") or "") == assessment.user
