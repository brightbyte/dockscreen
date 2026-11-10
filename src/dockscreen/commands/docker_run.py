"""This module implements `docker run`, and `dockscreen audit`, which says what `docker run` would do.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

With no user chosen on the command line, the policy decides it from the image (rules.image). Whatever
it accepts is not left for the runtime to resolve a second time: the container is re-created with
`--user uid:gid` as the checked numbers.

check creates the container and assesses it; gate starts it if it may run; audit creates it in the
same way, reports what `run` would do and removes it. The command line is trusted, so what it asks for
that a project or an image may not is pointed out (Policy.check_container), and fails the audit only with
--strict-screen.
"""

from collections.abc import Sequence
from typing import Any

from dockscreen.cli import runargs, userargs
from dockscreen.commands import helptext
from dockscreen.host.dockerclient import DockerError, DockerNotFound, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.container import Container
from dockscreen.model.image import Image
from dockscreen.model.origin import STRICT, TRUSTED, Origin
from dockscreen.screen import amendments, findings, hardening, userdecisionview
from dockscreen.screen.amendments import Amendment
from dockscreen.screen.findings import Finding, Reportable
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.report import Report
from dockscreen.screen.rules import idrules
from dockscreen.screen.screener import Screener
from dockscreen.screen.userdecision import UserDecision
from dockscreen.screen.userdecisionview import CHOOSE_HINT, explain, root_default_notice
from dockscreen.util import commandline, ids, messages
from dockscreen.util.messages import printable

AUDIT_USAGE = ("usage: dockscreen [--strict-screen] audit [--brief] [docker run options] "
               "IMAGE [COMMAND]")


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker run` through the gate and returns the exit status.

    The container starts only if the user it would run as is accepted, given as numbers where the image or the
    config chose it. Otherwise the refusal is printed and the status is 1, or docker's own if it could not
    create the container. Under --strict-screen, what the command line asks for that a project or an image
    may not have is refused too.

    Parameters:
    - parent_cli: the docker command line, with `run` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "run"
    screener = Screener(runtime, own_ids_hint=idrules.RUN_HINT)
    remote = is_remote(parent_cli.lead_args, runtime.docker)
    daemon = Report.of(screener.policy(runtime.cwd).check_daemon(remote))
    if not daemon.passed:
        return daemon.show()
    try:
        parsed = runargs.parse(parent_cli.args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        finding = Finding(f"cannot read the command line: {e}", help="use the real docker for this one")
        Report.of([finding]).show_screening()
        return 1
    users, parsed = userargs.screened(parsed, screener)
    if not users.passed:
        users.show()
        return 1
    root_default = root_default_notice(screener.policy(runtime.cwd).default_user)
    defaults = hardening.container_defaults()
    for message in [*users.notices, root_default, defaults.notice]:
        if message:
            messages.notice(message)

    created = _create_checked(screener, parsed, [defaults])
    if isinstance(created, int):
        return created
    container, decision = created
    if parent_cli.strict:
        found = Report.of(_command_line_findings(screener, container, decision, STRICT))
        if not found.passed:
            screener.docker.remove(container.id)
            found.show_screening()
            return 1

    if decision.pins_user:
        # All are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        screener.docker.remove(container.id)
        user = amendments.pinned_user(decision, parsed.image)
        for notice in amendments.notices(user):
            messages.notice(notice)
        created = _create_checked(screener, parsed, [defaults, *user], decision)
        if isinstance(created, int):
            return created
        container, decision = created

    Report().show_screening()
    return screener.docker.start(
        container.id,
        attach=not parsed.detach,
        # -i is kept by create; start needs it again
        interactive=bool(container.info["Config"].get("OpenStdin")),
        detach_keys=parsed.detach_keys,
    )


def _create_checked(screener: Screener, parsed: runargs.RunArgs, changes: Sequence[Amendment],
                    decided: UserDecision | None = None) -> tuple[Container, UserDecision] | int:
    """Creates the container (check); returns it with the decision of its user, or the exit status if it
    may not start.

    A container that would be refused is removed and the refusal printed. Any other decision is
    returned, for the caller to re-create the container with the user as numbers if it pins one.
    """
    code, created = check(screener, parsed, changes, decided)
    if created is None:  # docker said why
        Report.failure(f"docker could not create a container for {parsed.image}").show_screening()
        return code
    container, decision = created
    if decision.refused:
        screener.docker.remove(container.id)
        Report.of(explain(decision, screener.runtime.config_file)).show_screening()
        return 1
    return created


def check(screener: Screener, parsed: runargs.RunArgs, changes: Sequence[Amendment],
          decided: UserDecision | None = None) -> tuple[int, tuple[Container, UserDecision] | None]:
    """Creates the container as `docker run` would and returns (exit status, (container, decision of its
    user)), or (exit status, None) if docker could not create it; it said why.

    The container is left for the caller to remove.

    Parameters:
    - screener: the Screener of the command
    - parsed: the `docker run` command line, as parsed
    - changes: what goes before the command line's own arguments: the defaults, and the user decided
    - decided: the decision of a first creation, whose user changes pins; the container is then not assessed
      again, only checked to be what the command line asked for, and its user comes from where the decided one
      does
    """
    code, created = screener.docker.create(amendments.applied(parsed.create_args, changes))
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


def _command_line_findings(screener: Screener, container: Container, decision: UserDecision,
                           trust: frozenset[Origin]) -> list[Reportable]:
    """Returns what the command line asks for, in the container it created (check, with no options of
    dockscreen's own), that a project or an image may not have: refused, or a warning where trust trusts the
    command line (Policy.check_container).

    Empty if the container could not be inspected.
    """
    if not container.inspected:
        return []
    return screener.policy(screener.runtime.cwd, decision.section, trust).check_container(container)


def _user_origin(parsed: runargs.RunArgs, decided: UserDecision | None) -> Origin:
    """Returns where the user of the container comes from: where the decided one does, for a container
    re-created with it (check), else the command line if it gives one, else the image.
    """
    if decided is not None and decided.origin is not None:
        return decided.origin
    return Origin.COMMAND_LINE if parsed.users.chosen else Origin.IMAGE


def _verify_split(info: dict[str, Any], parsed: runargs.RunArgs) -> list[Finding]:
    """Checks that our reading of the command line matches the container the daemon created.

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


def audit(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Reports what `docker run` with the arguments of audit would do, without starting anything.

    The container is created as `run` would create it, pulling the image if `run` would, and removed. Returns
    the verdict as exit status: 1 if `run` would refuse, or with strict (--strict-screen) if the command line
    asks for something a project or an image may not; 3 if the audit failed to get that far; 2 if args cannot
    be read. --brief, before the image, prints only the verdict, in one line.

    Parameters:
    - parent_cli: the docker command line, with `audit` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "audit"
    if not parent_cli.args:
        messages.notice(AUDIT_USAGE)
        messages.notice("Run 'dockscreen audit --help' for more.")
        return 2

    line = parent_cli.subcommand(runargs.VALUE_OPTIONS, {commandline.BRIEF})
    brief, args = line.has_own(commandline.BRIEF), line.argv
    screener = Screener(runtime, own_ids_hint=idrules.RUN_HINT)
    daemon = Report.of(screener.policy(runtime.cwd).check_daemon(is_remote(parent_cli.lead_args,
                                                                            runtime.docker)))
    if not daemon.passed:
        return daemon.show(brief)
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        messages.notice(e)
        messages.notice(AUDIT_USAGE)
        return 2
    users, parsed = userargs.screened(parsed, screener)
    if not users.passed:
        return users.show(brief)
    if not brief:
        for message in users.notices:
            messages.notice(message)

    try:
        _, created = check(screener, parsed, [hardening.container_defaults()])
    except DockerNotFound as e:
        return Report.failure(str(e)).show(brief)
    if created is None:
        reason = f"docker could not create a container for {parsed.image}"
        return Report.failure(reason).show(brief)
    container, decision = created
    try:
        found = _command_line_findings(screener, container, decision, STRICT if line.strict else TRUSTED)
    finally:
        screener.docker.remove(container.id)

    refused = explain(decision, screener.runtime.config_file)
    outcome = Report.of([*refused, *found])
    if brief:
        messages.out(outcome.brief, indent=False)
    else:
        _report_decision(screener, parsed.image, decision)
        _report_findings(found)
        messages.notice(outcome.closing_line)
    return int(outcome.verdict)


def _report_decision(screener: Screener, image: str, decision: UserDecision) -> None:
    """Prints what `docker run` would do about the user the image runs as, and the defaults it adds."""
    name, dot = printable(image), userdecisionview.dot(decision)
    if decision.origin is Origin.COMMAND_LINE:
        messages.out(messages.Message(
            dot, f"image {name}: the user is set on the command line; the image's own user is not checked"))
    else:
        outcome = userdecisionview.outcome(decision, screener.local)
        messages.out(messages.Message(dot, f"image {name}: {outcome}"))
        for note in decision.notices:
            messages.out(Notice(f"note: {note}", NoticeSeverity.WARNING))
    if decision.refused:
        if not decision.failed:
            messages.out(messages.Message(messages.HINT, CHOOSE_HINT))
            hint = userdecisionview.config_hint(image, screener.runtime.config_file)
            messages.out(messages.Message(messages.HINT, hint))
        return
    if decision.pins_user:
        user = ids.format_user(decision.pinned_user)
        messages.out(f"  docker run would create it again with --user={user}, as numbers")
    defaults = " ".join(hardening.container_defaults().args)
    messages.out(f"  docker run also adds {defaults}; later options override them")


def _report_findings(found: list[Reportable]) -> None:
    """Prints what the command line asks for that a project or an image may not: as refusals, or as worth a
    look where the command line is trusted.
    """
    for finding in findings.about(found, "command line"):
        messages.out(finding)
    if any(isinstance(item, Notice) for item in found):
        messages.out(messages.Message(messages.HINT, "docker run allows these because you gave them; "
                                                   "--strict-screen makes them fail the audit"))


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it: run or audit
    """
    if name == "audit":
        return helptext.HelpTopic(
            f"dockscreen [{commandline.STRICT_SCREEN}] audit [{commandline.BRIEF}] "
            "[RUN OPTIONS] IMAGE [COMMAND] [ARG...]",
            "Say what run would do with the same arguments, without starting anything",
            (("The container is created as run would create it, pulling the image if run would, judged, and "
              "removed. It also points out what the command line asks for that a compose project or an "
              "image may not have; run allows that, because the command line is trusted."),
             ("Exit status: 0 audit passed, 1 denied by audit, 2 usage error, 3 audit failed (no docker, the "
              "image could not be pulled or created).")),
            (helptext.BRIEF,
             helptext.HelpOption(commandline.STRICT_SCREEN,
                                 "(before audit) Deny for what the command line asks for, too"),
             *helptext.USER_OPTIONS),
            docker_help=False)
    assert name == "run"
    return helptext.HelpTopic(
        "dockscreen run [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create and run a container, after checking the user its image runs as",
        ("dockscreen creates the container, checks it, and only then starts it:", *helptext.IMAGE_RULES,
         helptext.DEFAULTS, helptext.VERDICT),
        helptext.USER_OPTIONS, aliases=("dockscreen container run", "dockscreen run"))
