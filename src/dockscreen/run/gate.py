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
checked when it is started. `audit` (run/audit) creates the container as `run` does here and reports
what `run` would do.
"""

from dockscreen import argscan, daemon, hostusers, ids, imagedecision, images, messages, verdict
from dockscreen.dockerclient import DockerError
from dockscreen.imagedecision import (
    Assessment,
    Kind,
    assess,
    default_home,
    env_value,
    instead_of_root,
    root_default_notice,
)
from dockscreen.run import runargs
from dockscreen.verdict import Verdict

# Inserted before the user's own arguments, so the user can override both
# (for example `--cap-add NET_BIND_SERVICE`).
DEFAULTS = ["--cap-drop=ALL", "--security-opt=no-new-privileges:true"]
CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"


# Options of `docker start` and `restart` that take a value.
VALUE_LONG = frozenset({"--detach-keys", "--checkpoint", "--checkpoint-dir", "--signal", "--time"})
VALUE_SHORT = frozenset("st")


def run(global_args, args, runtime, allow_me=False):
    """Runs `docker global_args run args` through the gate and returns the exit status.

    The container starts only if the user it would run as is accepted, given as numbers where the image
    or the config chose it. Otherwise the refusal is printed and the status is 1, or docker's own if it
    could not create the container.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    if daemon.is_remote(global_args, runtime.env, runtime.docker):
        return verdict.report(Verdict.REFUSED, [daemon.REMOTE_MESSAGE])
    ctx = image_context(runtime, allow_me)
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
        user = ids.format_user(assessment.user)
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


def _home_args(ctx, info, assessment):
    """Returns `-e HOME=...` for the default user, unless the command line or an env file chose a HOME.

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
    """Returns the notice of the defaults `run` and `create` add to every container, as a marked line."""
    return messages.routine_change(
        f"added {' '.join(DEFAULTS)}",
        "a program that needs a capability or setuid fails: add --cap-add or --security-opt yourself, "
        "which override these")


def _fallback_notice(assessment):
    """Returns the notice that the default user replaces the image's root, and what to do about it."""
    home = default_home(assessment.user, assessment.home)
    return messages.notable_change(
        instead_of_root(assessment),
        f"the default user replaces root; {CHOOSE_HINT}; files and volumes set up for root may not be "
        "accessible to it" + (f", and its HOME is set to {home} unless you set it" if home else ""))


def _create_checked(ctx, parsed, extra):
    """Creates the container; returns (container, info, assessment), or the exit status if it may not start.

    A container that would be refused is removed and the refusal printed. Any other assessment is
    returned, for the caller to re-create the container with the user as numbers if it pins one.
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
    """Creates the container as `docker run` would and returns (exit status, container, info, assessment).

    extra: arguments that go before the command line's own. Without a container (docker could not
    create one; it said why) the others are None. The container is left for the caller to remove.
    """
    code, container = ctx.docker.create([*DEFAULTS, *extra, *parsed.create_args])
    if container is None:
        return code, None, None, None
    info = None
    try:
        info = ctx.docker.inspect_container(container)
        problems = _verify_split(info, parsed)  # a misread command line may hide a --user: assess nothing
        assessment = Assessment(Kind.REFUSED, problems) if problems else assess(
            ctx, container, info, explicit=parsed.user_given or bool(extra), reference=parsed.image)
    except (DockerError, ValueError, KeyError) as e:
        assessment = Assessment(Kind.FAILED, [str(e)])
    return code, container, info, assessment


def create_args(args, runtime):
    """Returns the arguments of `docker create` with --as and --as-me replaced by ids, and prints notices.

    Arguments that cannot be read are returned as they are: docker will report what is wrong with them.
    Raises hostusers.UserError for a user that cannot be used.
    """
    try:
        parsed = runargs.parse(args, runtime.me, runtime.accounts)
    except runargs.ParseError:
        return args
    for message in parsed.notices:
        messages.notice(message)
    return parsed.create_args


def check_existing(global_args, args, runtime, allow_me=False):
    """Returns the problems that forbid starting the containers named in `docker global_args start args`
    (or `restart`).

    An existing container cannot be rewritten, so one whose user dockscreen would replace (by the
    default user or a configured one) is refused like one whose user is not accepted, unless it
    already runs as that user.
    """
    if daemon.is_remote(global_args, runtime.env, runtime.docker):
        return [daemon.REMOTE_MESSAGE]
    ctx = image_context(runtime, allow_me)
    problems = []
    for ref in argscan.positionals(args, VALUE_LONG, VALUE_SHORT):
        try:
            info = ctx.docker.inspect_container(ref)
            assessment = assess(ctx, info["Id"], info)
            if assessment.replaces_image_user and not _runs_as_pinned_user(info, assessment):
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


def _runs_as_pinned_user(info, assessment):
    """Tells whether the container was created with the numeric user dockscreen would have chosen."""
    return ids.parse_user(info["Config"].get("User") or "") == assessment.user


def _verify_split(info, parsed):
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


def explain(ctx, assessment, image):
    """Returns the assessment's problems, with how to get past them if they come from the image's user."""
    if assessment.identity is None:
        return assessment.problems
    return [messages.Reason(p, f"{CHOOSE_HINT}, {config_hint(ctx, image)}") for p in assessment.problems]


def config_hint(ctx, image):
    """Returns the hint how the config file can give image a user, for an image pulled from a registry."""
    return f"or, for an image pulled from a registry, {images.section_hint(image, ctx.runtime.config_file)}"


def image_context(runtime, allow_me=False):
    """Returns the imagedecision.Context to create, decide and start with."""
    return imagedecision.Context(runtime.docker, runtime.rules(allow_me), runtime)
