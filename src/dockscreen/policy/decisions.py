"""This module defines the Decisions class, a record of what a policy decided about the users of a compose
project's services once dockscreen has looked at their images, with the substitutions that follow from it
(Policy.user_changes), and the functions for describing both.
"""

from collections.abc import Mapping, Sequence
from typing import NamedTuple, Self

from dockscreen.host import hostusers
from dockscreen.model.image import ImageInspection, UnseenImage
from dockscreen.model.project import Project
from dockscreen.policy import userdecisionview
from dockscreen.policy.finding import Finding
from dockscreen.policy.notice import Notice, NoticeSeverity
from dockscreen.policy.policy import Policy
from dockscreen.policy.projectpatch import ProjectPatch
from dockscreen.policy.report import Report
from dockscreen.policy.rules.userrules import USER_HELP
from dockscreen.policy.userdecision import UserDecision
from dockscreen.util import ids, messages


class Decisions(NamedTuple):
    """Record of what a policy decided about the users of a compose project's services once their images were
    looked at. It holds the project and the policy, the decision about each service, the report, and the
    substitutions that follow.

    Instances come from Screener.decide.

    Attributes:
    - project: the project decided about
    - policy: the policy that decided, with image sections only where the images proved them
    - by_service: by service, the UserDecision of each started service that sets no user; a dict that must not
      be changed in place
    - report: the failures to acquire the images, and the services whose image must not run
    - changes: the patch that makes the project the one to run
    - local_accounts: this host's accounts, for naming the users in describe
    """
    project: Project
    policy: Policy
    local_accounts: hostusers.HostAccounts
    by_service: dict[str, UserDecision]
    report: Report
    changes: ProjectPatch

    @classmethod
    def of(cls, project: Project, project_policy: Policy, local_accounts: hostusers.HostAccounts,
           inspections: Mapping[str,
                                ImageInspection | UnseenImage], failures: Sequence[Finding] = ()) -> Self:
        """Returns what project_policy decides about project from what was seen of its services' images, with
        the failures to acquire them.

        Parameters:
        - project: the project
        - project_policy: the policy that decides, with the image sections the images proved
        - local_accounts: this host's accounts, for naming the users
        - inspections: by service, what was seen of the images that decide the users
        - failures: the failures to pull, build or list its services
        """
        decisions = project_policy.assess_images(inspections)
        report = Report.of([*failures, *project_policy.check_images(inspections)])
        return cls(project, project_policy, local_accounts, decisions, report,
                   project_policy.user_changes(project, decisions))

    def describe(self) -> list[messages.HasMark]:
        """Describes, in one line per service that sets no user, what dockscreen does about it."""
        lines: list[messages.HasMark] = []
        decisions = self.by_service
        for name in sorted(self.project.services_without_user):
            decision = decisions.get(name)
            if decision is None:
                default_user = ids.format_user(self.policy.default_user)
                text = (f"no user set and not started by default; dockscreen runs it as the default user "
                        f"({default_user}) if it is started")
                lines.append(Notice(text, NoticeSeverity.WARNING, f"service {name}", USER_HELP))
                continue
            outcome = userdecisionview.outcome(decision, self.local_accounts)
            text = f"no user set; image {decision.image.reference} {outcome}"
            if decision.is_accepted:
                lines.append(messages.Message(userdecisionview.dot(decision), f"service {name}: {text}"))
            elif decision.replaces_root and not decision.is_refused:
                lines.append(Notice(text, NoticeSeverity.WARNING, f"service {name}", USER_HELP))
            for note in decision.notices:
                lines.append(Notice(f"note: {note}", NoticeSeverity.WARNING, f"service {name}"))
        return [*lines, *self.changes.group_notices()]

    def notices(self) -> list[Notice]:
        """Lists, as notices, what a run does that the project did not ask for."""
        return self.changes.notices()


