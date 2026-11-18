"""This module provides functions for describing a UserDecision: its mark, its meaning for running the image,
the reasons for a refusal, and the ways past a refusal.
"""

from dockscreen.host import hostusers
from dockscreen.model.image import section_hint
from dockscreen.model.origin import Origin
from dockscreen.policy import imageuser
from dockscreen.policy.finding import Finding
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.rules import userrules
from dockscreen.policy.userdecision import UserDecision
from dockscreen.util import ids, messages
from dockscreen.util.messages import printable_text


def dot(decision: UserDecision) -> messages.Mark:
    """Returns the mark for a decision of an image's user: BAD if refused, GOOD if accepted, else WARN."""
    if decision.is_refused:
        return messages.BAD
    return messages.GOOD if decision.is_accepted else messages.WARN


def outcome(decision: UserDecision, local_accounts: hostusers.HostAccounts) -> str:
    """Describes the meaning of a decision of an image's user for running the image, as text that follows the
    image's name. The text names the user that the image runs as if the decision accepts it, the user that
    runs instead of the image's root, or the reasons that the image may not run.

    Parameters:
    - decision: the UserDecision of the image
    - local_accounts: this host's accounts, for naming the image's user
    """
    identity_text = imageuser.describe(decision.identity, local_accounts) if decision.identity else None
    if decision.is_accepted and decision.origin is Origin.CONFIG:
        return f"runs as {ids.format_user(decision.pinned_user)}, the user the config file sets for it"
    if decision.is_accepted:
        return f"runs as {identity_text}; accepted"
    if decision.replaces_root and not decision.is_refused:
        return f"would run as {identity_text}; {userrules.instead_of_root(decision)}"
    reasons = "; ".join(printable_text(r.text) for r in decision.findings)
    if decision.has_failed:
        return f"could not be assessed: {reasons}"
    return "would be refused" + (f" (runs as {identity_text})" if identity_text else "") + f": {reasons}"


def root_default_notice(default_user: tuple[int, int]) -> Notice | None:
    """Returns the warning to give on every run if the configured default user is root, else None."""
    if 0 in default_user:
        default_user_text = ids.format_user(default_user)
        return Notice(f"the configured default user is {default_user_text}: images that would run as root "
                      "run as root",
                      NoticeSeverity.WARNING, help="set default_user in the config file to change it")
    return None


def explain(decision: UserDecision, config_file: str) -> list[Finding]:
    """Returns the decision's reasons. If they come from the image's user, each carries a hint on getting
    past the refusal.

    Parameters:
    - decision: the UserDecision of the image
    - config_file: where an image section can give the image a user
    """
    if not decision.identity:
        return list(decision.findings)
    help = f"{userrules.CHOOSE_HINT}, {config_hint(decision.image.reference, config_file)}"
    return [r.with_help(help) for r in decision.findings]


def explain_existing(decision: UserDecision, config_file: str) -> list[Finding]:
    """Returns the decision's reasons. If they come from the image's user, each carries a hint on giving the
    image a user in config_file. An existing container keeps the user that docker created it with, so
    choosing a user is no way out.

    Parameters:
    - decision: the UserDecision of the image of the container
    - config_file: where an image section can give the image a user
    """
    hint = section_hint(decision.image.reference, config_file, decision.image.is_built)
    if not decision.identity or hint is None:
        return list(decision.findings)
    return [r.with_help(f"for an image pulled from a registry, {hint}") for r in decision.findings]


def config_hint(image: str, config_file: str) -> str:
    """Returns the hint on giving image a user in config_file, for an image pulled from a registry."""
    return f"or, for an image pulled from a registry, {section_hint(image, config_file)}"
