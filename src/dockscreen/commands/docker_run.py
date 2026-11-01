"""This module implements `docker run`, and `dockscreen audit`, which says what `docker run` would do.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

With no user chosen on the command line, imagedecision decides it. Whatever it accepts is not left
for the runtime to resolve a second time: the container is re-created with `--user uid:gid` as the
checked numbers.

check creates the container and assesses it; gate starts it if it may run; audit creates it in the
same way, reports what `run` would do and removes it. The command line is trusted, so what it asks for
that a project or an image may not is pointed out (runpolicy), and fails the audit only with
--strict-screen.
"""

from collections.abc import Sequence
from typing import Any, NamedTuple

from dockscreen.cli import runargs
from dockscreen.cli.runargs import DEFAULTS, defaults_notice
from dockscreen.host import hostusers
from dockscreen.host.dockerclient import REMOTE_MESSAGE, DockerError, DockerNotFound, is_remote
from dockscreen.host.runtime import Runtime
from dockscreen.screen import imagedecision, imageuser, policy, runpolicy, verdict
from dockscreen.screen.imagedecision import (
    CHOOSE_HINT,
    Assessment,
    Kind,
    assess,
    default_home,
    env_value,
    explain,
    instead_of_root,
    root_default_notice,
    runs_as,
)
from dockscreen.screen.verdict import Verdict
from dockscreen.util import commandline, ids, messages
from dockscreen.util.messages import printable

AUDIT_USAGE = ("usage: dockscreen [--allow-me] [--strict-screen] audit [--brief] [docker run options] "
               "IMAGE [COMMAND]")


def gate(global_args: Sequence[str], args: list[str], runtime: Runtime, allow_me: bool = False) -> int:
    """Runs `docker global_args run args` through the gate and returns the exit status.

    The container starts only if the user it would run as is accepted, given as numbers where the image
    or the config chose it. Otherwise the refusal is printed and the status is 1, or docker's own if it
    could not create the container.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    if is_remote(global_args, runtime.docker):
        return verdict.report(Verdict.REFUSED, [REMOTE_MESSAGE])
    ctx = imagedecision.Context.for_runtime(runtime, allow_me)
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        verdict.screened([messages.Reason(f"cannot read the command line: {e}",
                                          "use the real docker for this one")])
        return 1
    except hostusers.UserError as e:
        verdict.screened([str(e)])
        return 1
    for message in [*parsed.notices, root_default_notice(ctx), defaults_notice()]:
        if message:
            messages.notice(message)
    ctx = ctx.with_allow_me(parsed.allow_me)

    created = _create_checked(ctx, parsed, [])
    if isinstance(created, int):
        return created
    container, info, assessment = created

    if assessment.pins_user:
        # All are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        ctx.docker.remove(container)
        user = ids.format_user(assessment.pinned_user)
        if assessment.kind is Kind.FALLBACK:
            messages.notice(_fallback_notice(assessment))
        else:
            messages.notice(messages.routine_change(
                f"image {parsed.image} runs as {user}, passed to docker as numbers"))
        extra = [f"--user={user}"]
        if assessment.kind is Kind.FALLBACK:
            extra += _home_args(ctx, info, assessment)
        created = _create_checked(ctx, parsed, extra)
        if isinstance(created, int):
            return created
        container, info, assessment = created

    verdict.screened([])
    return ctx.docker.start(
        container,
        attach=not parsed.detach,
        interactive=bool(info["Config"].get("OpenStdin")),  # -i is kept by create; start needs it again
        detach_keys=parsed.detach_keys,
    )


def _home_args(ctx: imagedecision.Context, info: dict[str, Any], assessment: Assessment) -> list[str]:
    """Returns `-e HOME=...` for the default user, unless the command line or an env file chose a HOME.

    The container as created has the merged environment: a HOME that differs from the image's own
    was set by the person running it, and stays.
    """
    home = default_home(assessment.pinned_user, assessment.home)
    if not home:
        return []
    image_env = ctx.docker.inspect_image(info["Image"])["Config"].get("Env")
    if env_value(info["Config"].get("Env"), "HOME") != env_value(image_env, "HOME"):
        return []
    return ["-e", f"HOME={home}"]


def _fallback_notice(assessment: Assessment) -> messages.Marked:
    """Returns the notice that the default user replaces the image's root, and what to do about it."""
    home = default_home(assessment.pinned_user, assessment.home)
    return messages.notable_change(
        instead_of_root(assessment),
        f"the default user replaces root; {CHOOSE_HINT}; files and volumes set up for root may not be "
        "accessible to it" + (f", and its HOME is set to {home} unless you set it" if home else ""))


class Created(NamedTuple):
    """Container that `docker run` created to be checked, with what inspecting it showed and the assessment
    of its user.
    """
    container: str
    info: dict[str, Any]     # as inspected; {} if it could not be
    assessment: Assessment


def _create_checked(ctx: imagedecision.Context, parsed: runargs.ParsedRun, extra: list[str]
                    ) -> Created | int:
    """Creates the container; returns (container, info, assessment), or the exit status if it may not start.

    A container that would be refused is removed and the refusal printed. Any other assessment is
    returned, for the caller to re-create the container with the user as numbers if it pins one.
    """
    code, created = check(ctx, parsed, extra)
    if created is None:  # docker said why
        verdict.screened([f"docker could not create a container for {parsed.image}"], failed=True)
        return code
    if created.assessment.refused:
        ctx.docker.remove(created.container)
        verdict.screened(explain(ctx, created.assessment, parsed.image), failed=created.assessment.failed)
        return 1
    return created


def check(ctx: imagedecision.Context, parsed: runargs.ParsedRun, extra: list[str]
          ) -> tuple[int, Created | None]:
    """Creates the container as `docker run` would and returns (exit status, Created or None).

    extra: arguments that go before the command line's own. None if docker could not create a
    container; it said why. The container is left for the caller to remove.
    """
    code, container = ctx.docker.create([*DEFAULTS, *extra, *parsed.create_args])
    if container is None:
        return code, None
    info: dict[str, Any] = {}
    try:
        info = ctx.docker.inspect_container(container)
        problems = _verify_split(info, parsed)  # a misread command line may hide a --user: assess nothing
        assessment = Assessment(Kind.REFUSED, problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra), reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment(Kind.FAILED, [messages.with_output(messages.reason_of(e))])
    return code, Created(container, info, assessment)


def _verify_split(info: dict[str, Any], parsed: runargs.ParsedRun) -> list[messages.Reason]:
    """Checks that our reading of the command line matches the container the daemon created.

    Returns the problem if it does not, else an empty list.
    """
    config = info["Config"]
    misread_image = config.get("Image") != parsed.image
    # without a command of its own the container has the image's Cmd, which says nothing about our reading
    misread_command = parsed.command and (config.get("Cmd") or []) != parsed.command
    if misread_image or misread_command:
        return [messages.Reason("could not reliably tell the image from the command line",
                                "use the real docker for this one")]
    return []


def audit(global_args: Sequence[str], args: list[str], runtime: Runtime, allow_me: bool = False,
          strict: bool = False) -> int:
    """Reports what `docker global_args run args` would do, without starting anything.

    The container is created as `run` would create it, pulling the image if `run` would, and removed.
    Returns the verdict as exit status: 1 if `run` would refuse, or with strict (--strict-screen) if the
    command line asks for something a project or an image may not; 3 if the audit failed to get that far;
    2 if args cannot be read. --brief, before the image, prints only the verdict, in one line.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    line = commandline.CommandLine(args, runargs.VALUE_OPTIONS, {commandline.BRIEF})
    brief, args = line.has(commandline.BRIEF), line.argv
    if is_remote(global_args, runtime.docker):
        return verdict.report(Verdict.REFUSED, [REMOTE_MESSAGE], brief)
    ctx = imagedecision.Context.for_runtime(runtime, allow_me)
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError as e:
        messages.notice(e)
        messages.notice(AUDIT_USAGE)
        return 2
    except hostusers.UserError as e:
        return verdict.report(Verdict.REFUSED, [str(e)], brief)
    if not brief:
        for message in parsed.notices:
            messages.notice(message)
    ctx = ctx.with_allow_me(parsed.allow_me)

    try:
        _, created = check(ctx, parsed, [])
    except DockerNotFound as e:
        return verdict.report(Verdict.FAILED, [str(e)], brief)
    if created is None:
        reason = f"docker could not create a container for {parsed.image}"
        return verdict.report(Verdict.FAILED, [reason], brief)
    container, info, assessment = created
    try:
        settings, _ = ctx.for_image(assessment.section)
        policy_ctx = policy.context_for(settings, ctx.directory, ctx.ids, ctx.runtime.config_file)
        found = runpolicy.findings(info, parsed.user_given, policy_ctx) if info else []
    finally:
        ctx.docker.remove(container)

    outcome, reasons = _audit_verdict(ctx, assessment, found, strict, parsed.image)
    if brief:
        messages.out(verdict.brief(outcome, reasons), indent=False)
    else:
        _report_assessment(ctx, parsed.image, assessment)
        _report_findings(found, strict)
        messages.notice(verdict.line(outcome))
    return int(outcome)


def _audit_verdict(ctx: imagedecision.Context, assessment: Assessment, found: list[str], strict: bool,
                   image: str) -> tuple[Verdict, list[str]]:
    """Returns the (verdict, reasons) of an audit: the assessment's, then the findings if strict."""
    refused = imagedecision.explain(ctx, assessment, image) if assessment.refused else []
    reasons = [*refused, *(found if strict else [])]
    if assessment.failed:
        return Verdict.FAILED, reasons
    return (Verdict.REFUSED if reasons else Verdict.PASSED), reasons


def _report_assessment(ctx: imagedecision.Context, image: str, assessment: Assessment) -> None:
    """Prints what `docker run` would do about the user the image runs as, and the defaults it adds."""
    name, dot = printable(image), verdict.dot(assessment)
    if assessment.kind is Kind.EXPLICIT:
        messages.out(messages.Marked(
            dot, f"image {name}: the user is set on the command line; the image's own user is not checked"))
    else:
        messages.out(messages.Marked(dot, f"image {name}: {_describe_outcome(ctx, assessment)}"))
        if assessment.note:
            messages.out(messages.Marked(messages.WARN, f"note: {assessment.note}"))
    if assessment.refused:
        if not assessment.failed:
            messages.out(messages.Marked(messages.HINT, imagedecision.CHOOSE_HINT))
            messages.out(messages.Marked(messages.HINT, imagedecision.config_hint(ctx, image)))
        return
    if assessment.pins_user:
        user = ids.format_user(assessment.pinned_user)
        messages.out(f"  docker run would create it again with --user={user}, as numbers")
    messages.out("  docker run also adds " + " ".join(runargs.DEFAULTS) + "; later options override them")


def _report_findings(found: list[str], strict: bool) -> None:
    """Prints what the command line asks for that a project or an image may not; as failures if strict."""
    dot = messages.BAD if strict else messages.WARN
    for finding in found:
        messages.out(messages.Marked(dot, f"command line: {finding}"))
    if found and not strict:
        messages.out(messages.Marked(messages.HINT, "docker run allows these because you gave them; "
                                                   "--strict-screen makes them fail the audit"))


def _describe_outcome(ctx: imagedecision.Context, assessment: Assessment) -> str:
    """Returns, as text, what the assessment means for running the image."""
    if assessment.kind in (Kind.OK, Kind.CONFIGURED):
        return runs_as(assessment, ctx.local)
    who = imageuser.describe(assessment.identity, ctx.local) if assessment.identity else None
    if assessment.kind is Kind.FALLBACK:
        return (f"would run as {who}; docker run would run it as the default user "
                f"({ids.format_user(assessment.pinned_user)}) instead")
    reasons = "; ".join(printable(p) for p in assessment.problems)
    if assessment.failed:
        return f"could not be assessed: {reasons}"
    return "would be refused" + (f" (runs as {who})" if who else "") + f": {reasons}"
