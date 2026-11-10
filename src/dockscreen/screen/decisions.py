"""This module defines the Decisions class, a record of what a policy decided about the users of a compose
project's services once their images were looked at, with the substitutions that follow from it
(Policy.user_changes), and the functions for describing both.
"""

from collections.abc import Mapping, Sequence
from typing import NamedTuple, Self

from dockscreen.host import hostusers
from dockscreen.model.image import Inspected, Unseen
from dockscreen.model.project import Project
from dockscreen.screen import userdecisionview
from dockscreen.screen.findings import Finding
from dockscreen.screen.notices import Notice, NoticeSeverity
from dockscreen.screen.policy import Policy
from dockscreen.screen.report import Report
from dockscreen.screen.rules.users import USER_HELP
from dockscreen.screen.substitutions import ProjectPatch
from dockscreen.screen.userdecision import UserDecision
from dockscreen.util import ids, messages


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
    - changes: the patch that makes the project the one to run
    - local: this host's accounts, for naming the users in describe
    """
    project: Project
    policy: Policy
    local: hostusers.HostAccounts
    decisions: dict[str, UserDecision]
    report: Report
    changes: ProjectPatch

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
                   project_policy.user_changes(project, decided))

    def describe(self) -> list[messages.HasMark]:
        """Describes, in one line per service that sets no user, what dockscreen does about it."""
        lines: list[messages.HasMark] = []
        decisions = self.decisions
        for name in sorted(self.project.services_without_user):
            decision = decisions.get(name)
            if decision is None:
                default = ids.format_user(self.policy.default_user)
                text = (f"no user set and not started by default; dockscreen runs it as the default user "
                        f"({default}) if it is started")
                lines.append(Notice(text, NoticeSeverity.WARNING, f"service {name}", USER_HELP))
                continue
            outcome = userdecisionview.outcome(decision, self.local)
            text = f"no user set; image {decision.image.reference} {outcome}"
            if decision.accepted:
                lines.append(messages.Message(userdecisionview.dot(decision), f"service {name}: {text}"))
            elif decision.replaces_root and not decision.refused:
                lines.append(Notice(text, NoticeSeverity.WARNING, f"service {name}", USER_HELP))
            for note in decision.notices:
                lines.append(Notice(f"note: {note}", NoticeSeverity.WARNING, f"service {name}"))
        return [*lines, *self.changes.group_notices()]

    def notices(self) -> list[Notice]:
        """Lists, as notices, what a run does that the project did not ask for."""
        return self.changes.notices()


