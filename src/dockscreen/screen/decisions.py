"""This module provides what the policy decided about the users of a compose project's services once their
images were looked at (Decisions), and what follows: the substitutions that make the project the one that
runs (changes), and how both are described.

A user dockscreen decided is pinned as numbers, `user: "uid:gid"`: the runtime reads neither passwd nor
group for that, so it cannot resolve the image's user to anything but what was checked. The image that was
checked is pinned too, by id unless the service builds it, with `pull_policy: never`, so that neither a pull
nor a moved tag changes what runs. A service that does not start and sets no user gets the default user,
in case it does get started: a mistake in working out what starts must fail safe.
"""

from collections.abc import Mapping
from typing import Any, NamedTuple

from dockscreen.host import hostusers
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import policy, substitutions, verdict
from dockscreen.screen.assessment import Assessment
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.substitutions import Group, Substitution
from dockscreen.util import ids, messages

PINNED = Group("services {services}: user, image id and pull_policy: never fixed to what was checked, "
               "in the generated file only")
USER_HELP = ("set user: on the service to choose one; the default user may not be able to use files and "
             "volumes set up for root")


class Decisions(NamedTuple):
    """What the policy for a project (policy) decides about its services' users from what was found of their
    images (Project.found_images, Project.inspected), with the failures to acquire the images; local: this
    host's accounts, for naming users.
    """
    project: Project
    policy: policy.Policy
    local: hostusers.HostAccounts
    failures: tuple[Finding, ...] = ()  # pulling, building or listing the services failed

    @property
    def decisions(self) -> dict[str, Assessment]:
        """Returns the decision about each started service that sets no user, by service."""
        return self.policy.assess_images(self.project)

    @property
    def report(self) -> Report:
        """Returns the failures to acquire the images, and the services whose image must not run."""
        return Report.of([*self.failures, *self.policy.check_images(self.project)])

    def changes(self) -> list[Substitution]:
        """Returns the substitutions that make the project the one to run (the function changes)."""
        return changes(self.project, self.decisions, self.policy)

    def describe(self) -> list[messages.Marked]:
        """Describes, in one line per service that sets no user, what dockscreen does about it."""
        lines: list[messages.Marked] = []
        decisions = self.decisions
        for name in sorted(self.project.services_without_user):
            decision = decisions.get(name)
            if decision is None:
                default = ids.format_user(self.policy.default_user)
                text = (f"no user set and not started by default; dockscreen runs it as the default user "
                        f"({default}) if it is started")
                lines.append(Finding(text, Severity.NOTABLE, f"service {name}", USER_HELP))
                continue
            if decision.accepted:
                runs_as = verdict.runs_as(decision, self.local)
                text = f"service {name}: no user set; image {decision.image.reference} {runs_as}"
                lines.append(messages.Marked(verdict.dot(decision), text))
            elif decision.replaces_root and not decision.refused:
                instead = verdict.instead_of_root(decision)
                lines.append(Finding(f"no user set; {instead}", Severity.NOTABLE, f"service {name}",
                                     USER_HELP))
            for note in decision.notes:
                lines.append(Finding(f"note: {note}", Severity.NOTABLE, f"service {name}"))
        return [*lines, *substitutions.grouped(self.changes())]

    def notices(self) -> list[Finding]:
        """Lists, as routine and notable findings, what a run does that the project did not ask for."""
        return substitutions.describe(self.changes())


def changes(project: Project, decisions: Mapping[str, Assessment], project_policy: policy.Policy
            ) -> list[Substitution]:
    """Returns the substitutions that make project the one to run, by service name: services that start
    and set no user get the decided user (decisions), pinned to the image that was checked; those that do
    not start get the default user of project_policy, with its default_home as HOME (the function
    default_home).
    """
    found = []
    for name, service in sorted((project.definition.get("services") or {}).items()):
        service = service or {}
        if service.get("user"):
            continue
        decision = decisions.get(name)
        if decision is None:  # not started by this command
            found += _user(name, service, project_policy.default_user, project_policy.default_home,
                           project_policy.default_origin)
        elif decision.pins_user:
            found += _pinned(name, service, decision)
    return found


def _user(name: str, service: dict[str, Any], user: tuple[int, int], home: str, origin: Origin | None,
          text: str | None = None, group: Group | None = None) -> list[Substitution]:
    """Returns the substitutions that set the service's user to the default one, which comes from origin,
    reported by text if given, and the HOME that comes with it (default_home) unless the service sets HOME.
    """
    found = [Substitution(name, "user", ids.format_user(user), text, notable=bool(text),
                          help=USER_HELP if text else None, group=group, origin=origin)]
    if home := default_home(user, home):
        found.append(Substitution(name, "environment", {"HOME": home, **(service.get("environment") or {})}))
    return found


def _pinned(name: str, service: dict[str, Any], assessment: Assessment) -> list[Substitution]:
    """Returns the substitutions that pin a started service to what the assessment of its image checked:
    the user, as numbers, the image by id unless it is built, and pull_policy never.
    """
    if assessment.replaces_root:
        found = _user(name, service, assessment.pinned_user, assessment.home, assessment.origin,
                      verdict.instead_of_root(assessment), PINNED)
    else:  # the image's user, or the one its image section configures
        found = [Substitution(name, "user", ids.format_user(assessment.pinned_user), group=PINNED,
                              origin=assessment.origin)]
    # the image checked is what runs
    found.append(Substitution(name, "pull_policy", "never", group=PINNED, origin=Origin.DOCKSCREEN))
    if assessment.image.id and "build" not in service:
        # ... even if the name is moved to another image
        found.append(Substitution(name, "image", assessment.image.id, group=PINNED, origin=Origin.DOCKSCREEN))
    return found


# The default user owns nothing of the image's, and the image's HOME (root's, usually) is not its own.
def default_home(user: tuple[int, int], home: str) -> str:
    """Returns the HOME for a default user (uid, gid) that replaces an image's root user, or "" for none.

    home: the configured default_home. Root keeps its own.
    """
    return "" if 0 in user else home
