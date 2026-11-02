"""This module defines how the verdict of screening a command or of an audit is reported (see findings for
what the verdicts mean), and how the decision about a container's user is described.
"""

from dockscreen.host import hostusers
from dockscreen.model.image import section_hint
from dockscreen.screen import imageuser
from dockscreen.screen.assessment import Assessment, Kind
from dockscreen.screen.findings import Finding, Report, Severity, Verdict
from dockscreen.util import ids, messages
from dockscreen.util.messages import printable

CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"

ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}


def dot(assessment: Assessment) -> messages.Mark:
    """Returns the mark for an assessment of an image's user: BAD if refused, GOOD if accepted, else WARN."""
    if assessment.refused:
        return messages.BAD
    return messages.GOOD if assessment.kind in (Kind.IMAGE, Kind.CONFIGURED) else messages.WARN


# The closing line, the same for an audit, for --brief and for the check before a command runs.
LINES = {Verdict.PASSED: "audit passed", Verdict.REFUSED: "denied by audit", Verdict.FAILED: "audit failed"}


def line(verdict: Verdict) -> messages.Marked:
    """Builds the closing line of an audit, or of the check before a command runs: mark and verdict."""
    return messages.Marked(ICONS[verdict], LINES[verdict])


def brief(found: Report) -> messages.Marked:
    """Builds the verdict of what was found as one line, for --brief: the closing line, then the first
    reason if it did not pass and how many more there are.
    """
    verdict, reasons = found.verdict, found.reasons
    if verdict is Verdict.PASSED:
        return line(verdict)
    first = printable(messages.with_output(reasons[0]))
    more = f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else ""
    return messages.Marked(ICONS[verdict], f"{LINES[verdict]}: {first}{more}")


def report(found: Report, brief_mode: bool = False) -> int:
    """Prints the verdict of what was found and returns it as the exit status.

    brief_mode: print one line on stdout (brief); otherwise each finding that does not stop the command,
    each reason and the closing line go to stderr.
    """
    verdict = found.verdict
    if brief_mode:
        messages.out(brief(found), indent=False)
        return int(verdict)
    for finding in found.findings:
        if not finding.fatal:
            mark = messages.WARN if finding.severity is Severity.NOTABLE else messages.ROUTINE
            messages.notice(messages.Marked(mark, finding, finding.help, finding.output))
    for reason in found.reasons:
        text = f"refusing: {reason}" if verdict is Verdict.REFUSED else reason
        messages.notice(messages.Marked(messages.BAD, text, reason.help, reason.output))
    messages.notice(line(verdict))
    return int(verdict)


def screened(found: Report) -> bool:
    """Prints the verdict of screening a command and returns whether it may run."""
    report(found)
    return found.passed


# --- the user a container runs as ---------------------------------------------------

def runs_as(assessment: Assessment, local: hostusers.HostAccounts) -> str:
    """Describes what an accepted image (Kind.IMAGE or Kind.CONFIGURED) runs as; local: HostAccounts."""
    if assessment.kind is Kind.CONFIGURED:
        return f"runs as {ids.format_user(assessment.pinned_user)}, the user the config file sets for it"
    assert assessment.identity is not None, "an accepted image was looked at"
    return f"runs as {imageuser.describe(assessment.identity, local)}; accepted"


def instead_of_root(assessment: Assessment) -> str:
    """Describes what a Kind.FALLBACK assessment does instead of running as root."""
    return f"running as {ids.format_user(assessment.pinned_user)} instead of root"


def root_default_notice(default_user: tuple[int, int]) -> messages.Marked | None:
    """Returns the warning to give on every run if the configured default user is root, else None."""
    if 0 in default_user:
        default = ids.format_user(default_user)
        return messages.Marked(
            messages.WARN,
            f"the configured default user is {default}: images that would run as root run as root",
            "set default_user in the config file to change it")
    return None


def explain(assessment: Assessment, config_file: str) -> list[Finding]:
    """Returns the assessment's reasons, with how to get past them if they come from the image's user;
    config_file: where an image section can give the image a user.
    """
    if not assessment.identity:
        return assessment.reasons
    help = f"{CHOOSE_HINT}, {config_hint(assessment.image.reference, config_file)}"
    return [Finding(r.text, r.severity, r.subject, help, r.output) for r in assessment.reasons]


def config_hint(image: str, config_file: str) -> str:
    """Returns the hint how config_file can give image a user, for an image pulled from a registry."""
    return f"or, for an image pulled from a registry, {section_hint(image, config_file)}"
