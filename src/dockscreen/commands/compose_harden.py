"""`docker compose harden` (and `fix`), dockscreen's own: a compose override that fixes what can be fixed.

`global_args` are the compose-level options that preceded the subcommand (e.g. ["-f", "x.yml"]), which
select the project.
"""

import sys
from collections.abc import Sequence
from typing import Any

from dockscreen.compose import autofix, composeimages, composeproject, hardening, inspect
from dockscreen.host.dockerclient import REMOTE_MESSAGE
from dockscreen.host.runtime import Runtime
from dockscreen.screen import policy
from dockscreen.util import messages


def harden(global_args: list[str], args: Sequence[str], runtime: Runtime, allow_me: bool = False) -> int:
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
        project = composeproject.load_project(global_args, runtime, allow_me=True)
    except (inspect.ScreenError, ValueError) as e:
        messages.notice(messages.reason_of(e))
        return 1
    if project.remote:
        messages.notice(REMOTE_MESSAGE)
        return 1

    base, static = project.hardened, project.static_ctx()
    fixed = autofix.fix_config(base, static)
    # what the patch runs as, as compose would read it; compose interpolates the generated file and makes
    # its paths absolute, so ${UID} or ./ETC there would read back differently from what was checked
    resolved = autofix.as_compose_reads(fixed, static)
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


def _fix_image_users(project: composeproject.Project, fixed: dict[str, Any], resolved: dict[str, Any],
                     notes: list[str]) -> tuple[list[str], list[str]]:
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

