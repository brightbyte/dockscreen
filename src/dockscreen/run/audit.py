"""`dockscreen audit`: what `docker run` would do with a command line, without starting anything.

The container is created as the gate creates it for `run`, assessed the same way, and removed. The
command line is trusted, so what it asks for that a project or an image may not is pointed out
(runpolicy), and fails the audit only with --strict-screen.
"""

from dockscreen import commandline, daemon, hostusers, ids, imageuser, messages, policy, verdict
from dockscreen.dockerclient import DockerNotFound
from dockscreen.imagedecision import Kind, runs_as
from dockscreen.messages import printable
from dockscreen.run import gate, runargs, runpolicy
from dockscreen.verdict import Verdict


AUDIT_USAGE = ("usage: dockscreen [--allow-me] [--strict-screen] audit [--brief] [docker run options] "
               "IMAGE [COMMAND]")


def audit(global_args, args, runtime, allow_me=False, strict=False):
    """Reports what `docker global_args run args` would do, without starting anything.

    The container is created as `run` would create it, pulling the image if `run` would, and removed.
    Returns the verdict as exit status: 1 if `run` would refuse, or with strict (--strict-screen) if the
    command line asks for something a project or an image may not; 3 if the audit failed to get that far;
    2 if args cannot be read. --brief, before the image, prints only the verdict, in one line.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    line = commandline.CommandLine(args, runargs.VALUE_OPTIONS, {commandline.BRIEF})
    brief, args = line.has(commandline.BRIEF), line.argv
    if daemon.is_remote(global_args, runtime.env, runtime.docker):
        return verdict.report(Verdict.REFUSED, [daemon.REMOTE_MESSAGE], brief)
    ctx = gate.image_context(runtime, allow_me)
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
        _, container, info, assessment = gate.create_assessed(ctx, parsed, [])
    except DockerNotFound as e:
        return verdict.report(Verdict.FAILED, [str(e)], brief)
    if container is None:
        reason = f"docker could not create a container for {parsed.image}"
        return verdict.report(Verdict.FAILED, [reason], brief)
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


def _audit_verdict(ctx, assessment, found, strict, image):
    """Returns the (verdict, reasons) of an audit: the assessment's, then the findings if strict."""
    refused = gate.explain(ctx, assessment, image) if assessment.refused else []
    reasons = [*refused, *(found if strict else [])]
    if assessment.failed:
        return Verdict.FAILED, reasons
    return (Verdict.REFUSED if reasons else Verdict.PASSED), reasons


def _report_assessment(ctx, image, assessment):
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
            messages.out(messages.Marked(messages.HINT, gate.CHOOSE_HINT))
            messages.out(messages.Marked(messages.HINT, gate.config_hint(ctx, image)))
        return
    if assessment.pins_user:
        user = ids.format_user(assessment.user)
        messages.out(f"  docker run would create it again with --user={user}, as numbers")
    messages.out("  docker run also adds " + " ".join(gate.DEFAULTS) + "; later options override them")


def _report_findings(found, strict):
    """Prints what the command line asks for that a project or an image may not; as failures if strict."""
    dot = messages.BAD if strict else messages.WARN
    for finding in found:
        messages.out(messages.Marked(dot, f"command line: {finding}"))
    if found and not strict:
        messages.out(messages.Marked(messages.HINT, "docker run allows these because you gave them; "
                                                   "--strict-screen makes them fail the audit"))


def _describe_outcome(ctx, assessment):
    """Returns, as text, what the assessment means for running the image."""
    if assessment.kind in (Kind.OK, Kind.CONFIGURED):
        return runs_as(assessment, ctx.local)
    who = imageuser.describe(assessment.identity, ctx.local) if assessment.identity else None
    if assessment.kind is Kind.FALLBACK:
        return (f"would run as {who}; docker run would run it as the default user "
                f"({ids.format_user(assessment.user)}) instead")
    reasons = "; ".join(printable(p) for p in assessment.problems)
    if assessment.failed:
        return f"could not be assessed: {reasons}"
    return "would be refused" + (f" (runs as {who})" if who else "") + f": {reasons}"
