"""This module implements `docker run`, and `dockscreen audit`, which reports the outcome of `docker run`
without starting anything.

`docker run` becomes create, inspect, check, start. The daemon parses the command line and creates the
container, from an image that cannot change between the check and the start. The policy then looks at that
container. The only fact that the policy takes from the image is the identity the container would run as (see
imageuser). It does not check that identity when the command line sets a user: the user typing the command is
trusted, and the image is not.

With no user chosen on the command line, the policy decides it from the image (rules.userrules). dockscreen
does not leave a user it accepts for the runtime to resolve a second time: it creates the container again with
`--user uid:gid` as the checked numbers.

The function gate creates the container, has the policy decide its user (containerscreening.create), and
starts the container if it may run. The function audit creates the container in the same way, reports the
outcome of `run`, and removes the container. The command line is trusted, so audit only points out its
requests that a project or an image may not make (containerscreening.command_line_findings). They fail the
audit only with --strict-screen.
"""


from dockscreen.commands import helptext
from dockscreen.host.docker import DockerNotFoundError, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.model.container import Container
from dockscreen.model.origin import STRICT_ORIGINS, TRUSTED_ORIGINS, Origin
from dockscreen.policy import finding, hardening, userdecisionview
from dockscreen.policy.commandlinepatch import CommandLinePatch
from dockscreen.policy.finding import Finding, ReportEntry
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.report import Report
from dockscreen.policy.rules import userrules
from dockscreen.policy.userdecision import UserDecision
from dockscreen.policy.userdecisionview import explain, root_default_notice
from dockscreen.screen import containerscreening, runargs, userscreening
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline, ids, messages
from dockscreen.util.messages import printable_text

AUDIT_USAGE = ("usage: dockscreen [--strict-screen] audit [--brief] [docker run options] "
               "IMAGE [COMMAND]")


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker run` through the gate and returns the exit status.

    The container starts only if the policy accepts the user it would run as. If the image or the config chose
    that user, the container gets the user as numbers. If the policy does not accept the user, this prints the
    refusal and returns 1. If docker could not create the container, this returns docker's own status. Under
    --strict-screen, the policy also refuses the command line's requests that a project or an image may not
    make.

    Parameters:
    - parent_cli: the docker command line, with `run` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "run"
    screener = Screener(runtime, own_ids_hint=userrules.RUN_HINT)
    is_remote_daemon = is_remote(parent_cli.lead_args, runtime.docker)
    daemon_report = Report.of(screener.policy(runtime.cwd).check_daemon(is_remote_daemon))
    if not daemon_report.has_passed:
        return daemon_report.show()
    try:
        parsed_args = runargs.parse(parent_cli.args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        refusal = Finding(f"cannot read the command line: {e}", help="use the real docker for this one")
        Report.of([refusal]).show_screening()
        return 1
    user_report, run_args = userscreening.screen_user_options(parsed_args, screener)
    if run_args is None:
        user_report.show()
        return 1
    default_user_notice = root_default_notice(screener.policy(runtime.cwd).default_user)
    default_patch = hardening.container_defaults()
    for message in [*user_report.notices, default_user_notice, *default_patch.notices()]:
        if message:
            messages.print_notice(message)

    creation_result = _create_and_check(screener, run_args, default_patch)
    if isinstance(creation_result, int):
        return creation_result
    container, decision = creation_result
    if parent_cli.is_strict:
        strict_report = Report.of(
            containerscreening.command_line_findings(screener, container, decision, STRICT_ORIGINS))
        if not strict_report.has_passed:
            screener.docker.remove(container.id)
            strict_report.show_screening()
            return 1

    if decision.pins_user:
        # dockscreen creates every container again, with the user given as numbers. The runtime then has
        # nothing to resolve in the image, whatever the image's passwd and group files say.
        screener.docker.remove(container.id)
        user_patch = screener.policy(runtime.cwd).user_amendments(decision, run_args.image)
        for notice in user_patch.notices():
            messages.print_notice(notice)
        creation_result = _create_and_check(screener, run_args, default_patch + user_patch, decision)
        if isinstance(creation_result, int):
            return creation_result
        container, decision = creation_result

    Report().show_screening()
    return screener.docker.start(
        container.id,
        should_attach=not run_args.should_detach,
        # create keeps -i, but start needs it again
        should_be_interactive=bool(container.info["Config"].get("OpenStdin")),
        detach_keys=run_args.detach_keys,
    )


def _create_and_check(screener: Screener, run_args: runargs.RunArgs[str], changes: CommandLinePatch,
                      first_decision: UserDecision | None = None) -> tuple[Container, UserDecision] | int:
    """Creates the container (containerscreening.create). Returns it with the decision on its user, or the
    exit status if it may not start.

    This removes a container that the policy refuses and prints the refusal. It returns any other decision,
    for the calling code to re-create the container with the user as numbers, if the decision pins a user.
    """
    code, creation_result = containerscreening.create(screener, run_args, changes, first_decision)
    if creation_result is None:  # docker said why
        Report.failure(f"docker could not create a container for {run_args.image}").show_screening()
        return code
    container, decision = creation_result
    if decision.is_refused:
        screener.docker.remove(container.id)
        Report.of(explain(decision, screener.runtime.config_file)).show_screening()
        return 1
    return creation_result


def audit(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Reports the outcome of `docker run` with the arguments of audit, without starting anything.

    This creates the container as `run` would create it, pulling the image if `run` would, and then removes
    the container. Returns the verdict as the exit status. The status is 1 if `run` would refuse; under
    --strict-screen, it is also 1 if the command line asks for something that a project or an image may not
    have. It is 3 if the audit failed to get that far, and 2 if the arguments cannot be read. With --brief,
    given before the image, this prints only the verdict, in one line.

    Parameters:
    - parent_cli: the docker command line, with `audit` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "audit"
    if not parent_cli.args:
        messages.print_notice(AUDIT_USAGE)
        messages.print_notice("Run 'dockscreen audit --help' for more.")
        return 2

    line = parent_cli.subcommand(runargs.VALUE_OPTIONS, {commandline.BRIEF_OPTION})
    is_brief, args = line.has_own(commandline.BRIEF_OPTION), line.argv
    screener = Screener(runtime, own_ids_hint=userrules.RUN_HINT)
    is_remote_daemon = is_remote(parent_cli.lead_args, runtime.docker)
    daemon_report = Report.of(screener.policy(runtime.cwd).check_daemon(is_remote_daemon))
    if not daemon_report.has_passed:
        return daemon_report.show(is_brief)
    try:
        parsed_args = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        messages.print_notice(e)
        messages.print_notice(AUDIT_USAGE)
        return 2
    user_report, run_args = userscreening.screen_user_options(parsed_args, screener)
    if run_args is None:
        return user_report.show(is_brief)
    if not is_brief:
        for message in user_report.notices:
            messages.print_notice(message)

    try:
        _, creation_result = containerscreening.create(screener, run_args, hardening.container_defaults())
    except DockerNotFoundError as e:
        return Report.failure(str(e)).show(is_brief)
    if creation_result is None:
        reason = f"docker could not create a container for {run_args.image}"
        return Report.failure(reason).show(is_brief)
    container, decision = creation_result
    try:
        trust = STRICT_ORIGINS if line.is_strict else TRUSTED_ORIGINS
        findings = containerscreening.command_line_findings(screener, container, decision, trust)
    finally:
        screener.docker.remove(container.id)

    refusals = explain(decision, screener.runtime.config_file)
    outcome = Report.of([*refusals, *findings])
    if is_brief:
        messages.print_line(outcome.brief_line, should_indent=False)
    else:
        _report_decision(screener, run_args.image, decision)
        _report_findings(findings)
        messages.print_notice(outcome.closing_line)
    return int(outcome.verdict)


def _report_decision(screener: Screener, image: str, decision: UserDecision) -> None:
    """Prints the outcome of `docker run` for the user that the image runs as, and the defaults that `run`
    adds.
    """
    name, dot = printable_text(image), userdecisionview.dot(decision)
    if decision.origin is Origin.COMMAND_LINE:
        messages.print_line(messages.Message(
            dot, f"image {name}: the user is set on the command line; the image's own user is not checked"))
    else:
        outcome = userdecisionview.outcome(decision, screener.local_accounts)
        messages.print_line(messages.Message(dot, f"image {name}: {outcome}"))
        for note in decision.notices:
            messages.print_line(Notice(f"note: {note}", NoticeSeverity.WARNING))
    if decision.is_refused:
        if not decision.has_failed:
            messages.print_line(messages.Message(messages.HINT, userrules.CHOOSE_HINT))
            hint = userdecisionview.config_hint(image, screener.runtime.config_file)
            messages.print_line(messages.Message(messages.HINT, hint))
        return
    if decision.pins_user:
        user = ids.format_user(decision.pinned_user)
        messages.print_line(f"  docker run would create it again with --user={user}, as numbers")
    default_args = " ".join(hardening.container_defaults().args)
    messages.print_line(f"  docker run also adds {default_args}; later options override them")


def _report_findings(findings: list[ReportEntry]) -> None:
    """Prints the command line's requests that a project or an image may not make. It prints them as refusals,
    or, where the command line is trusted, as worth a look.
    """
    for item in finding.with_subject(findings, "command line"):
        messages.print_line(item)
    if any(isinstance(item, Notice) for item in findings):
        messages.print_line(messages.Message(messages.HINT, "docker run allows these because you gave them; "
                                             "--strict-screen makes them fail the audit"))


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it: run or audit
    """
    if name == "audit":
        return helptext.HelpTopic(
            f"dockscreen [{commandline.STRICT_SCREEN_OPTION}] audit [{commandline.BRIEF_OPTION}] "
            "[RUN OPTIONS] IMAGE [COMMAND] [ARG...]",
            "Report the outcome of run with the same arguments, without starting anything",
            (("dockscreen creates the container as run would, pulling the image if run would. It then judges "
              "the container and removes it. It also points out the command line's requests that a compose "
              "project or an image may not make; run allows them, because the command line is trusted."),
             ("Exit status: 0 audit passed, 1 denied by audit, 2 usage error, 3 audit failed (no docker, the "
              "image could not be pulled or created).")),
            (helptext.BRIEF_HELP,
             helptext.HelpOption(commandline.STRICT_SCREEN_OPTION,
                                 "(before audit) Also deny the command line's requests"),
             *helptext.USER_OPTIONS),
            has_docker_help=False)
    assert name == "run"
    return helptext.HelpTopic(
        "dockscreen run [OPTIONS] IMAGE [COMMAND] [ARG...]",
        "Create and run a container, after checking the user its image runs as",
        ("dockscreen creates the container, checks it, and only then starts it:", *helptext.IMAGE_RULES,
         helptext.DEFAULTS, helptext.VERDICT),
        helptext.USER_OPTIONS, aliases=("dockscreen container run", "dockscreen run"))
