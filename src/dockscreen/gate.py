"""The gate in front of commands that start a container from an image.

`docker run` becomes create, inspect, check, start: the daemon parses the
command line, and the policy looks at the container it produced, from an image
that cannot change between check and start. The one image-derived fact checked
is the identity the container would run as (see imageuser), unless the command
line sets a user: the person typing the command is trusted, the image is not.

With no user chosen on the command line, imagedecision decides it. Whatever it accepts is not left
for the runtime to resolve a second time: the container is re-created with `--user uid:gid` as the
checked numbers.

`start` and `restart` apply the same check to existing containers, which cannot
be rewritten. `create` only gets the hardening defaults; its container is
checked when it is started. `audit` takes a `docker run` command line, creates its container as
`run` would and reports what `run` would do, then removes it; it also points out what the command line
asks for that a project or an image may not (runpolicy).
"""

from dockscreen import (
    argscan,
    flags,
    hostusers,
    ids,
    images,
    imageuser,
    messages,
    policy,
    runargs,
    runpolicy,
    verdict,
)
from dockscreen.dockerclient import DockerError, DockerNotFound
from dockscreen.imagedecision import (
    Assessment,
    Kind,
    assess,
    default_home,
    env_value,
    instead_of_root,
    root_default_notice,
    runs_as,
)
from dockscreen.messages import printable
from dockscreen.verdict import Verdict

# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"


# Options of `docker start` and `restart` that take a value.
VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


def run(ctx, args):
    """`docker run`; returns the exit code."""
    try:
        parsed = runargs.parse(args, ctx.runtime.me, ctx.runtime.accounts)
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
    ctx = ctx.allowing_me(parsed.allow_me)

    created = create_checked(ctx, parsed, [])
    if isinstance(created, int):
        return created
    container, info, assessment = created

    if assessment.pins_user:
        # All are re-created with the user spelled as numbers: the runtime then has nothing of the
        # image's to resolve, whatever its passwd and group files say.
        ctx.docker.remove(container)
        user = ids.format_user(assessment.user)
        if assessment.kind is Kind.FALLBACK:
            messages.notice(fallback_notice(assessment))
        else:
            messages.notice(messages.routine_change(
                f"image {parsed.image} runs as {user}, passed to docker as numbers"))
        extra = [f"--user={user}"]
        if assessment.kind is Kind.FALLBACK:
            extra += home_args(ctx, info, assessment)
        created = create_checked(ctx, parsed, extra)
        if isinstance(created, int):
            return created
        container, info, assessment = created

    verdict.screened([])
    return ctx.docker.start(
        container,
        attach=not parsed.detach,
        interactive=bool(info["Config"].get("OpenStdin")),
        detach_keys=parsed.detach_keys,
    )


def home_args(ctx, info, assessment):
    """`-e HOME=...` for the default user, unless the command line or an env file chose a HOME.

    The container as created has the merged environment: a HOME that differs from the image's own
    was set by the person running it, and stays.
    """
    home = default_home(assessment.user, assessment.home)
    if not home:
        return []
    image_env = ctx.docker.inspect_image(info["Image"])["Config"].get("Env")
    if env_value(info["Config"].get("Env"), "HOME") != env_value(image_env, "HOME"):
        return []
    return ["-e", f"HOME={home}"]


def defaults_notice():
    """The change `run` and `create` make to every container, as a marked line."""
    return messages.routine_change(
        f"added {' '.join(DEFAULTS)}",
        "a program that needs a capability or setuid fails: add --cap-add or --security-opt yourself, "
        "which override these")


def fallback_notice(assessment):
    home = default_home(assessment.user, assessment.home)
    return messages.notable_change(
        instead_of_root(assessment),
        f"the default user replaces root; {CHOOSE_HINT}; files and volumes set up for root may not be "
        "accessible to it" + (f", and its HOME is set to {home} unless you set it" if home else ""))


def create_checked(ctx, parsed, extra):
    """Create the container; (container, info, assessment), or an exit code if it must not start.

    A container that would be refused is removed. Any other assessment is returned to the caller,
    which re-creates the container with the user as numbers.
    """
    code, container, info, assessment = create_assessed(ctx, parsed, extra)
    if container is None:  # docker said why
        verdict.screened([f"docker could not create a container for {parsed.image}"], failed=True)
        return code
    if assessment.refused:
        ctx.docker.remove(container)
        verdict.screened(explain(ctx, assessment, parsed.image), failed=assessment.failed)
        return 1
    return container, info, assessment


def create_assessed(ctx, parsed, extra):
    """Create the container as `docker run` would and assess it: (exit code, container, info, assessment).

    extra: arguments that go before the command line's own. Without a container (docker could not
    create one; it said why) the others are None. The container is left for the caller to remove.
    """
    code, container = ctx.docker.create([*DEFAULTS, *extra, *parsed.create_args])
    if container is None:
        return code, None, None, None
    info = None
    try:
        info = ctx.docker.inspect_container(container)
        problems = verify_split(info, parsed)
        assessment = Assessment(Kind.REFUSED, problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra), reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment(Kind.FAILED, [str(e)])
    return code, container, info, assessment


AUDIT_USAGE = ("usage: dockscreen [--allow-me] [--strict-screen] audit [--brief] [docker run options] "
               "IMAGE [COMMAND]")


def audit(ctx, args, strict=False):
    """`audit` with a `docker run` command line: what `docker run` would do with it, without starting it.

    The container is created as `run` would create it, pulling the image if `run` would, and removed.
    The exit status is the verdict: 1 if `run` would refuse, or with strict (--strict-screen) if the
    command line asks for something a project or an image may not; 3 if the audit failed to get that far.
    --brief, before the image, prints only the verdict, in one line.
    """
    brief, args = flags.strip(args, runargs.VALUE_OPTIONS, flags.BRIEF)
    try:
        parsed = runargs.parse(args, ctx.runtime.me, ctx.runtime.accounts)
    except runargs.ParseError as e:
        messages.notice(e)
        messages.notice(AUDIT_USAGE)
        return 2
    except hostusers.UserError as e:
        return verdict.report(Verdict.REFUSED, [str(e)], brief)
    if not brief:
        for message in parsed.notices:
            messages.notice(message)
    ctx = ctx.allowing_me(parsed.allow_me)

    try:
        _, container, info, assessment = create_assessed(ctx, parsed, [])
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

    outcome, reasons = audit_verdict(ctx, assessment, found, strict, parsed.image)
    if brief:
        messages.out(verdict.brief(outcome, reasons), indent=False)
    else:
        report_assessment(ctx, parsed.image, assessment)
        report_findings(found, strict)
        messages.notice(verdict.line(outcome))
    return int(outcome)


def audit_verdict(ctx, assessment, found, strict, image):
    """(verdict, reasons) of an audit: the assessment's, then the command line's findings if strict."""
    reasons = [*(explain(ctx, assessment, image) if assessment.refused else []), *(found if strict else [])]
    if assessment.failed:
        return Verdict.FAILED, reasons
    return (Verdict.REFUSED if reasons else Verdict.PASSED), reasons


def report_assessment(ctx, image, assessment):
    """Print what `docker run` would do about the user."""
    name, dot = printable(image), verdict.dot(assessment)
    if assessment.kind is Kind.EXPLICIT:
        messages.out(messages.Marked(
            dot, f"image {name}: the user is set on the command line; the image's own user is not checked"))
    else:
        messages.out(messages.Marked(dot, f"image {name}: {describe_outcome(ctx, assessment)}"))
        if assessment.note:
            messages.out(messages.Marked(messages.WARN, f"note: {assessment.note}"))
    if assessment.refused:
        if not assessment.failed:
            messages.out(messages.Marked(messages.HINT, CHOOSE_HINT))
            messages.out(messages.Marked(messages.HINT, config_hint(ctx, image)))
        return
    if assessment.pins_user:
        user = ids.format_user(assessment.user)
        messages.out(f"  docker run would create it again with --user={user}, as numbers")
    messages.out("  docker run also adds " + " ".join(DEFAULTS) + "; later options override them")


def report_findings(found, strict):
    """Print what the command line asks for that a project or an image may not."""
    dot = messages.BAD if strict else messages.WARN
    for finding in found:
        messages.out(messages.Marked(dot, f"command line: {finding}"))
    if found and not strict:
        messages.out(messages.Marked(messages.HINT, "docker run allows these because you gave them; "
                                                   "--strict-screen makes them fail the audit"))


def describe_outcome(ctx, assessment):
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


def create_args(args, runtime):
    """The arguments of `docker create` with --as and --as-me replaced by ids, and --user checked.

    Returned as they are if they cannot be read: docker will report what is wrong with them.
    """
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:
        return args
    for message in parsed.notices:
        messages.notice(message)
    return parsed.create_args


def check_existing(ctx, args):
    """Problems for the containers named in `docker start`/`restart` arguments.

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the
    default user or a configured one) is refused like one whose user is not accepted, unless it
    already runs as that user.
    """
    problems = []
    for ref in argscan.positionals(args, VALUE_LONG, VALUE_SHORT):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            if assessment.replaces_image_user and not runs_as_pinned_user(info, assessment):
                user = ids.format_user(assessment.user)
                problems.append(messages.Reason(
                    f"{ref}: cannot change the user of an existing container; it would run as the "
                    f"image's user, not as {user}", f"recreate it with --user {user}"))
            else:
                image = info["Config"].get("Image") or ""
                problems += [messages.Reason(f"{ref}: {p}", messages.help_of(p))
                             for p in explain(ctx, assessment, image)]
        except (DockerError, ValueError, KeyError) as e:
            problems.append(f"{ref}: {e}")
    return problems


def runs_as_pinned_user(info, assessment):
    """Whether the container was created with the numeric user dockscreen would have chosen."""
    return ids.parse_user(info["Config"].get("User") or "") == assessment.user


def verify_split(info, parsed):
    """Our reading of the command line must match what the daemon created, or we refuse."""
    config = info["Config"]
    misread_image = config.get("Image") != parsed.image
    misread_command = parsed.command and (config.get("Cmd") or []) != parsed.command
    if misread_image or misread_command:
        return [messages.Reason("could not reliably tell the image from the command line",
                                "use the real docker for this one")]
    return []


def explain(ctx, assessment, image):
    """The problems, with how to get past them when they come from the image's own identity."""
    if assessment.identity is None:
        return assessment.problems
    return [messages.Reason(p, f"{CHOOSE_HINT}, {config_hint(ctx, image)}") for p in assessment.problems]


def config_hint(ctx, image):
    """How the config file could give the image a user, if docker records it as pulled."""
    return f"or, for an image pulled from a registry, {images.section_hint(image, ctx.runtime.config_file)}"
