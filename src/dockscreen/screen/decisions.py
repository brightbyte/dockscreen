"""This module defines the Decisions class, a record of what a policy decided about the users of a compose
project's services once their images were looked at, with functions for working out the substitutions that
follow from it and for describing both.

A user dockscreen decided is pinned as numbers, `user: "uid:gid"`: the runtime reads neither passwd nor
group for that, so it cannot resolve the image's user to anything but what was checked. The image that was
checked is pinned too, by id unless the service builds it, with `pull_policy: never`, so that neither a pull
nor a moved tag changes what runs. A service that does not start and sets no user gets the default user,
in case it does get started: a mistake in working out what starts must fail safe.
"""

from collections.abc import Mapping, Sequence
from typing import Any, NamedTuple, Self

from dockscreen.host import hostusers
from dockscreen.model.image import Inspected, Unseen
from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import substitutions, userdecisionview
from dockscreen.screen.findings import Finding, Report, Severity
from dockscreen.screen.policy import Policy
from dockscreen.screen.substitutions import Substitution, SubstitutionGroup
from dockscreen.screen.userdecision import UserDecision
from dockscreen.util import ids, messages

PINNED = SubstitutionGroup(
    "services {services}: user, image id and pull_policy: never fixed to what was checked, "
    "in the generated file only")
USER_HELP = ("set user: on the service to choose one; the default user may not be able to use files and "
             "volumes set up for root")


class Decisions(NamedTuple):
    """Record of what a policy decided about the users of a compose project's services once their images were
    looked at. It holds the project and the policy, the decision about each service, the report, and the
    substitutions that follow.

    Instances come from Screener.decide.

    Attributes:
    - project: the project decided about
    - policy: the policy that decided, with image sections only where the images proved them
    - decisions: by service, the UserDecision of each started service that sets no user; a dict that must not
      be changed in place
    - report: the failures to acquire the images, and the services whose image must not run
    - changes: the substitutions that make the project the one to run
    - local: this host's accounts, for naming the users in describe
    """
    project: Project
    policy: Policy
    local: hostusers.HostAccounts
    decisions: dict[str, UserDecision]
    report: Report
    changes: tuple[Substitution, ...]

    @classmethod
    def of(cls, project: Project, project_policy: Policy, local: hostusers.HostAccounts,
           inspected: Mapping[str, Inspected | Unseen], failures: Sequence[Finding] = ()) -> Self:
        """Returns what project_policy decides about project from what was seen of its services' images, with
        the failures to acquire them.

        Parameters:
        - project: the project
        - project_policy: the policy that decides, with the image sections the images proved
        - local: this host's accounts, for naming the users
        - inspected: by service, what was seen of the images that decide the users
        - failures: the failures to pull, build or list its services
        """
        decided = project_policy.assess_images(inspected)
        report = Report.of([*failures, *project_policy.check_images(inspected)])
        return cls(project, project_policy, local, decided, report,
                   tuple(changes(project, decided, project_policy)))

    def describe(self) -> list[messages.Message]:
        """Describes, in one line per service that sets no user, what dockscreen does about it."""
        lines: list[messages.Message] = []
        decisions = self.decisions
        for name in sorted(self.project.services_without_user):
            decision = decisions.get(name)
            if decision is None:
                default = ids.format_user(self.policy.default_user)
                text = (f"no user set and not started by default; dockscreen runs it as the default user "
                        f"({default}) if it is started")
                lines.append(Finding(text, Severity.NOTABLE, f"service {name}", USER_HELP))
                continue
            outcome = userdecisionview.outcome(decision, self.local)
            text = f"no user set; image {decision.image.reference} {outcome}"
            if decision.accepted:
                lines.append(messages.Message(userdecisionview.dot(decision), f"service {name}: {text}"))
            elif decision.replaces_root and not decision.refused:
                lines.append(Finding(text, Severity.NOTABLE, f"service {name}", USER_HELP))
            for note in decision.notes:
                lines.append(Finding(f"note: {note}", Severity.NOTABLE, f"service {name}"))
        return [*lines, *substitutions.grouped(self.changes)]

    def notices(self) -> list[Finding]:
        """Lists, as routine and notable findings, what a run does that the project did not ask for."""
        return substitutions.describe(self.changes)


def changes(project: Project, decisions: Mapping[str, UserDecision], project_policy: Policy
            ) -> list[Substitution]:
    """Returns the substitutions that make project the one to run, by service name: services that start
    and set no user get the decided user (decisions), pinned to the image that was checked; those that do
    not start get the default user of project_policy, with its default_home as HOME (the function
    default_home).

    Parameters:
    - project: the project
    - decisions: by service, the UserDecision of each started service that sets no user
    - project_policy: the policy that decided, which gives the default user and default_home
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
          text: str | None = None, group: SubstitutionGroup | None = None) -> list[Substitution]:
    """Returns the substitutions that set the service's user to the default one, which comes from origin,
    reported by text if given, and the HOME that comes with it (default_home) unless the service sets HOME.
    """
    found = [Substitution(name, "user", ids.format_user(user), text, notable=bool(text),
                          help=USER_HELP if text else None, group=group, origin=origin)]
    if home := default_home(user, home):
        found.append(Substitution(name, "environment", {"HOME": home, **(service.get("environment") or {})}))
    return found


def _pinned(name: str, service: dict[str, Any], decision: UserDecision) -> list[Substitution]:
    """Returns the substitutions that pin a started service to what the decision of its image checked:
    the user, as numbers, the image by id unless it is built, and pull_policy never.
    """
    if decision.replaces_root:
        found = _user(name, service, decision.pinned_user, decision.home, decision.origin,
                      userdecisionview.instead_of_root(decision), PINNED)
    else:  # the image's user, or the one its image section configures
        found = [Substitution(name, "user", ids.format_user(decision.pinned_user), group=PINNED,
                              origin=decision.origin)]
    # the image checked is what runs
    found.append(Substitution(name, "pull_policy", "never", group=PINNED, origin=Origin.DOCKSCREEN))
    if decision.image.id and "build" not in service:
        # ... even if the name is moved to another image
        found.append(Substitution(name, "image", decision.image.id, group=PINNED, origin=Origin.DOCKSCREEN))
    return found


# The default user owns nothing of the image's, and the image's HOME (root's, usually) is not its own.
def default_home(user: tuple[int, int], home: str) -> str:
    """Returns the HOME for a default user (uid, gid) that replaces an image's root user, or "" for none.

    Root keeps its own.

    Parameters:
    - user: the default user's (uid, gid)
    - home: the configured default_home
    """
    return "" if 0 in user else home
