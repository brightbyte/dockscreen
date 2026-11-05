"""This module implements `docker start` and `docker restart`, with the same check as `run`, on containers
that already exist.

An existing container cannot be rewritten, so one whose user dockscreen would replace (by the default
user or a configured one) is refused like one whose user is not accepted, unless it already runs as
that user.

Docker does not record where a container was created, and its labels, which its image can set, prove
nothing. So it is judged without a directory: no project section of the config file applies, and only
the configured mount_dirs allow bind mounts.
"""

from typing import Any

from dockscreen.commands import helptext
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


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker start` or `restart` if every container it names passes check; returns 1 if one does not,
    otherwise docker replaces this process.

    Parameters:
    - parent_cli: the docker command line, with `start` or `restart` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd in ("start", "restart")
    if not verdict.screened(Report.of(check(parent_cli, runtime))):
        return 1
    runtime.docker.exec(parent_cli.argv)


def check(cli: commandline.CommandLine, runtime: Runtime) -> list[Finding]:
    """Returns the refusals that forbid starting the containers that the `docker start` (or `restart`)
    command line cli names.

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the default user
    or a configured one) is refused like one whose user is not accepted, unless it already runs as that user.

    Parameters:
    - cli: the docker command line, with `start` or `restart` as its command. With --allow-me in it, the
      caller's own ids are allowed; with --strict-screen, what the command line that created a container
      asked for is judged as a project's would be, and refused (Policy.check_container)
    - runtime: the Runtime of the command
    """
    screener = Screener(runtime, cli.allow_me)
    if is_remote(cli.lead_args, runtime.docker):
        return screener.policy(None).check_daemon(True)
    problems: list[Finding] = []
    for ref in commandline.positionals(cli.args, VALUE_LONG, VALUE_SHORT):
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
            if cli.strict:
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


def help(name: str) -> helptext.Topic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it: start or restart
    """
    if name == "restart":
        return helptext.Topic(
            "dockscreen restart [OPTIONS] CONTAINER [CONTAINER...]",
            "Restart containers, denied if they would fail the check of run",
            ("As for start.", helptext.VERDICT),
            aliases=("dockscreen container restart", "dockscreen restart"))
    assert name == "start"
    return helptext.Topic(
        "dockscreen start [OPTIONS] CONTAINER [CONTAINER...]",
        "Start containers, denied if they would fail the check of run",
        (("An existing container cannot be changed, so one whose image's user dockscreen would replace or "
          "deny is denied."), helptext.VERDICT),
        aliases=("dockscreen container start", "dockscreen start"))
