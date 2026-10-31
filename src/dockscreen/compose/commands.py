"""Custom subcommands.

A command is a callable(global_args, args, runtime, allow_me) -> exit code. `global_args` are the
compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), so
a command can pass them on when it shells out to docker compose.

A name in COMMANDS shadows the docker compose subcommand of the same name.
"""

import sys

from dockscreen import daemon, flags, messages, policy, verdict
from dockscreen.compose import autofix, composeimages, composerun, hardening, screen, shellenv
from dockscreen.dockerclient import DockerNotFound
from dockscreen.verdict import Verdict

HARDEN_HINT = "the harden subcommand prints a compose override file with these fixes"


def _audit(global_args, args, runtime, allow_me=False):
    """Runs the checks that screen `up` without starting anything; pulls and builds images as up would.

    Exit status 0 if `up` would run, 1 if it would refuse, 3 if the audit failed to get that far
    (verdict). --brief prints only the verdict, in one line.
    """
    brief = args == [flags.BRIEF]
    if args and not brief:
        messages.notice(f"usage: dockscreen compose [compose options] audit [{flags.BRIEF}]")
        return 2
    try:
        project = composerun.load_project(global_args, runtime, allow_me)
    except (screen.InspectError, DockerNotFound) as e:
        return verdict.report(Verdict.FAILED, [str(e)], brief)
    except (screen.ScreenError, ValueError) as e:
        return verdict.report(Verdict.REFUSED, [str(e)], brief)

    outcome, problems, lines = _audit_images(project, brief)
    if not brief:
        warnings = [*screen.mount_dir_warnings(runtime), *shellenv.describe(project.hardened, runtime.env)]
        for line in [*hardening.describe(project.additions), *warnings, *lines]:
            messages.out(line)
        if problems or project.additions:
            messages.out(messages.Marked(messages.HINT, HARDEN_HINT))
    return verdict.report(outcome, problems, brief)


def _audit_images(project, brief):
    """Checks the project, then its images if the checks pass.

    Returns (verdict, problems, report lines).
    """
    problems = project.problems()
    if problems:
        return Verdict.REFUSED, problems, [
            "the images were not looked at because of the problems below: nothing was pulled or built"]
    if not brief:
        messages.notice("pulling or building the images as `up` would, to look at the users they run as")
    hardened, image_ctx = project.hardened, project.image_ctx
    with project.generated() as command:
        prepared = composeimages.prepare(command(hardened), hardened, [], image_ctx)
    problems = prepared.problems
    if not problems:  # what `up` checks once more before it runs: image sections need proof now
        final, vetted = prepared.finalize()
        problems = policy.check_config(final, project.final_ctx(prepared, vetted))
    outcome = Verdict.FAILED if prepared.failed else Verdict.REFUSED if problems else Verdict.PASSED
    return outcome, problems, prepared.describe()


def _harden(global_args, args, runtime, allow_me=False):
    """Prints a compose override that fixes what can be fixed; exits with 1 if problems remain.

    The patch is relative to the merged config as dockscreen will run it, defaults
    included: only what is needed on top of them to pass the audit is written out,
    and one comment says what is added automatically. Mount sources outside the
    project become placeholders to edit; problems without a safe automatic fix are
    listed as comments. Images are pulled and built first, as `up` would, to see
    which services need a user of their own.

    A user that has to be set becomes `${UID}:${GID}`, the caller's own, so the result is checked as
    if --allow-me were given, and the patch says that it needs it.
    """
    try:
        project = composerun.load_project(global_args, runtime, allow_me=True)
    except (screen.ScreenError, ValueError) as e:
        messages.notice(e)
        return 1
    if project.remote:
        messages.notice(daemon.REMOTE_MESSAGE)
        return 1

    base, static = project.hardened, project.static_ctx()
    fixed = autofix.fix_config(base, static)
    # what the patch runs as, with ${UID}:${GID} as compose would read it; compose interpolates the
    # generated file too, so a literal ${UID} there would read back differently from what was checked
    resolved = autofix.resolve_user_template(fixed, static)
    remaining = policy.check_config(resolved, static)
    notes = [hardening.defaults_note()]
    if remaining:
        messages.notice("the images were not looked at because of the problems below: "
                        "nothing was pulled or built")
    else:
        remaining, notes = _fix_image_users(project, fixed, resolved, notes)

    sys.stdout.write(autofix.render(base, fixed, remaining, notes=notes))
    for problem in remaining:
        messages.notice(f"cannot fix automatically: {problem}")
    return 1 if remaining else 0


def _fix_image_users(project, fixed, resolved, notes):
    """Sets a user in fixed on the services whose image chose one that is not acceptable.

    Returns (problems left, notes). resolved: fixed as it will run, which is what the images are looked at
    with.
    """
    with project.generated() as command:
        prepared = composeimages.prepare(command(resolved), resolved, [], project.image_ctx)
    if not prepared.decisions:
        return prepared.problems, notes  # nothing could be looked at: pulling or building failed
    remaining = []
    for name, decision in prepared.decisions.items():
        if decision.assessment.failed:  # setting a user does not fix an image that could not be read
            remaining.append(composeimages.decision_problem(name, decision))
        elif decision.assessment.refused:
            fixed["services"][name]["user"] = autofix.USER_TEMPLATE
            notes.append(f"service {name}: image {decision.image} chose a user that is not acceptable, "
                         "so user is set explicitly")
    return remaining, notes


COMMANDS = {"audit": _audit, "harden": _harden, "fix": _harden}
ALIASES = {"fix": "harden"}  # alias -> command it stands for
