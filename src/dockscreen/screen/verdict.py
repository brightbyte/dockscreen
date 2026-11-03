"""This module provides functions for reporting the verdict of screening a command or of an audit (see
findings for what the verdicts mean), and for describing a decision about a container's user."""

from dockscreen.host import hostusers
from dockscreen.model.image import section_hint
from dockscreen.model.origin import Origin
from dockscreen.screen import imageuser
from dockscreen.screen.assessment import Assessment
from dockscreen.screen.findings import Finding, Report, Severity, Verdict
from dockscreen.util import ids, messages
from dockscreen.util.messages import printable

CHOOSE_HINT = "pass --user UID:GID, --as NAME or --as-me to choose a user"

ICONS = {Verdict.PASSED: messages.PASSED, Verdict.REFUSED: messages.REFUSED, Verdict.FAILED: messages.FAILED}


def dot(assessment: Assessment) -> messages.Mark:
    """Returns the mark for an assessment of an image's user: BAD if refused, GOOD if accepted, else WARN."""
    if assessment.refused:
        return messages.BAD
    return messages.GOOD if assessment.accepted else messages.WARN


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

    Parameters:
    - found: the report
    - brief_mode: print one line on stdout (brief); otherwise each finding that does not stop the command,
      each reason and the closing line go to stderr
    """
    verdict = found.verdict
    if brief_mode:
        messages.out(brief(found), indent=False)
        return int(verdict)
    for finding in found.findings:
        if not finding.fatal:
            messages.notice(finding)
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

def outcome(assessment: Assessment, local: hostusers.HostAccounts) -> str:
    """Describes what an assessment of an image's user means for running it, after the image's name: what it
    runs as if accepted, what runs instead of its root, or why it may not run.

    Parameters:
    - assessment: the Assessment of the image
    - local: this host's accounts, for naming the image's user
    """
    who = imageuser.describe(assessment.identity, local) if assessment.identity else None
    if assessment.accepted and assessment.origin is Origin.CONFIG:
        return f"runs as {ids.format_user(assessment.pinned_user)}, the user the config file sets for it"
    if assessment.accepted:
        return f"runs as {who}; accepted"
    if assessment.replaces_root and not assessment.refused:
        return f"would run as {who}; {instead_of_root(assessment)}"
    reasons = "; ".join(printable(r.text) for r in assessment.reasons)
    if assessment.failed:
        return f"could not be assessed: {reasons}"
    return "would be refused" + (f" (runs as {who})" if who else "") + f": {reasons}"


def instead_of_root(assessment: Assessment) -> str:
    """Describes what an assessment that replaces_root does instead of running as root."""
    return f"running as {ids.format_user(assessment.pinned_user)} instead of root"


def root_default_notice(default_user: tuple[int, int]) -> Finding | None:
    """Returns the notable finding to give on every run if the configured default user is root, else None."""
    if 0 in default_user:
        default = ids.format_user(default_user)
        return Finding(f"the configured default user is {default}: images that would run as root run as root",
                       Severity.NOTABLE, help="set default_user in the config file to change it")
    return None


def explain(assessment: Assessment, config_file: str) -> list[Finding]:
    """Returns the assessment's reasons, with how to get past them if they come from the image's user;

    Parameters:
    - assessment: the Assessment of the image
    - config_file: where an image section can give the image a user
    """
    if not assessment.identity:
        return assessment.reasons
    help = f"{CHOOSE_HINT}, {config_hint(assessment.image.reference, config_file)}"
    return [Finding(r.text, r.severity, r.subject, help, r.output) for r in assessment.reasons]


def config_hint(image: str, config_file: str) -> str:
    """Returns the hint how config_file can give image a user, for an image pulled from a registry."""
    return f"or, for an image pulled from a registry, {section_hint(image, config_file)}"
