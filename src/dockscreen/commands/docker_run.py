"""This module implements `docker run`, and `dockscreen audit`, which says what `docker run` would do.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

With no user chosen on the command line, the policy decides it from the image (rules.userrules). Whatever
it accepts is not left for the runtime to resolve a second time: the container is re-created with
`--user uid:gid` as the checked numbers.

gate creates the container and has its user decided (containerscreening.create), and starts it if it may
run; audit creates it in the same way, reports what `run` would do and removes it. The command line is
trusted, so what it asks for that a project or an image may not is pointed out
(containerscreening.command_line_findings), and fails the audit only with --strict-screen.
"""


from dockscreen.commands import helptext
from dockscreen.host.docker import DockerNotFound, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.container import Container
from dockscreen.model.origin import STRICT, TRUSTED, Origin
from dockscreen.policy import finding, hardening, userdecisionview
from dockscreen.policy.commandlinepatch import CommandLinePatch
from dockscreen.policy.finding import Finding, Reportable
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.report import Report
from dockscreen.policy.rules import userrules
from dockscreen.policy.userdecision import UserDecision
from dockscreen.policy.userdecisionview import CHOOSE_HINT, explain, root_default_notice
from dockscreen.screen import containerscreening, runargs, userscreening
from dockscreen.screen.screener import Screener
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
    screener = Screener(runtime, own_ids_hint=userrules.RUN_HINT)
    remote = is_remote(parent_cli.lead_args, runtime.docker)
    daemon = Report.of(screener.policy(runtime.cwd).check_daemon(remote))
    if not daemon.passed:
        return daemon.show()
    try:
        read = runargs.parse(parent_cli.args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        refusal = Finding(f"cannot read the command line: {e}", help="use the real docker for this one")
        Report.of([refusal]).show_screening()
        return 1
    given, parsed = userscreening.screened(read, screener)
    if parsed is None:
        given.show()
        return 1
    root_default = root_default_notice(screener.policy(runtime.cwd).default_user)
    defaults = hardening.container_defaults()
    for message in [*given.notices, root_default, *defaults.notices()]:
        if message:
            messages.notice(message)

    created = _create_checked(screener, parsed, defaults)
    if isinstance(created, int):
        return created
    container, decision = created
    if parent_cli.strict:
        found = Report.of(containerscreening.command_line_findings(screener, container, decision, STRICT))
        if not found.passed:
            screener.docker.remove(container.id)
            found.show_screening()
            return 1

    if decision.pins_user:
        # All are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        screener.docker.remove(container.id)
        user = screener.policy(runtime.cwd).user_amendments(decision, parsed.image)
        for notice in user.notices():
            messages.notice(notice)
        created = _create_checked(screener, parsed, defaults + user, decision)
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


def _create_checked(screener: Screener, parsed: runargs.RunArgs[str], changes: CommandLinePatch,
                    decided: UserDecision | None = None) -> tuple[Container, UserDecision] | int:
    """Creates the container (containerscreening.create); returns it with the decision of its user, or the
    exit status if it may not start.

    A container that would be refused is removed and the refusal printed. Any other decision is
    returned, for the caller to re-create the container with the user as numbers if it pins one.
    """
    code, created = containerscreening.create(screener, parsed, changes, decided)
    if created is None:  # docker said why
        Report.failure(f"docker could not create a container for {parsed.image}").show_screening()
        return code
    container, decision = created
    if decision.refused:
        screener.docker.remove(container.id)
        Report.of(explain(decision, screener.runtime.config_file)).show_screening()
        return 1
    return created


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
    screener = Screener(runtime, own_ids_hint=userrules.RUN_HINT)
    daemon = Report.of(screener.policy(runtime.cwd).check_daemon(is_remote(parent_cli.lead_args,
                                                                            runtime.docker)))
    if not daemon.passed:
        return daemon.show(brief)
    try:
        read = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        messages.notice(e)
        messages.notice(AUDIT_USAGE)
        return 2
    given, parsed = userscreening.screened(read, screener)
    if parsed is None:
        return given.show(brief)
    if not brief:
        for message in given.notices:
            messages.notice(message)

    try:
        _, created = containerscreening.create(screener, parsed, hardening.container_defaults())
    except DockerNotFound as e:
        return Report.failure(str(e)).show(brief)
    if created is None:
        reason = f"docker could not create a container for {parsed.image}"
        return Report.failure(reason).show(brief)
    container, decision = created
    try:
        trust = STRICT if line.strict else TRUSTED
        found = containerscreening.command_line_findings(screener, container, decision, trust)
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
    for item in finding.about(found, "command line"):
        messages.out(item)
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
