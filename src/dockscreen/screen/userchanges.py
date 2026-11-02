"""This module provides the substitutions that follow from the decisions about the users of a compose
project's services (Policy.assess_images), which make the project the one that runs.

A user dockscreen decided is pinned as numbers, `user: "uid:gid"`: the runtime reads neither passwd nor
group for that, so it cannot resolve the image's user to anything but what was checked. The image that was
checked is pinned too, by id unless the service builds it, with `pull_policy: never`, so that neither a pull
nor a moved tag changes what runs. A service that does not start and sets no user gets the default user,
in case it does get started: a mistake in working out what starts must fail safe.
"""

from collections.abc import Mapping
from typing import Any

from dockscreen.model.origin import Origin
from dockscreen.model.project import Project
from dockscreen.screen import verdict
from dockscreen.screen.assessment import Assessment, Kind
from dockscreen.screen.substitutions import Group, Substitution
from dockscreen.util import ids

PINNED = Group("services {services}: user, image id and pull_policy: never fixed to what was checked, "
               "in the generated file only")
USER_HELP = ("set user: on the service to choose one; the default user may not be able to use files and "
             "volumes set up for root")


def changes(project: Project, decisions: Mapping[str, Assessment], default_user: tuple[int, int],
            default_home: str) -> list[Substitution]:
    """Returns the substitutions that make project the one to run, by service name: services that start
    and set no user get the decided user (decisions), pinned to the image that was checked; those that do
    not start get default_user, with default_home as HOME (the function default_home).
    """
    found = []
    for name, service in sorted((project.definition.get("services") or {}).items()):
        service = service or {}
        if service.get("user"):
            continue
        decision = decisions.get(name)
        if decision is None:  # not started by this command
            found += _user(name, service, default_user, default_home)
        elif decision.pins_user:
            found += _pinned(name, service, decision)
    return found


def _user(name: str, service: dict[str, Any], user: tuple[int, int], home: str, text: str | None = None,
          group: Group | None = None) -> list[Substitution]:
    """Returns the substitutions that set the service's user, the configured or the default one, reported
    by text if given, and the HOME that comes with the default user (default_home) unless the service sets
    HOME.
    """
    found = [Substitution(name, "user", ids.format_user(user), text, notable=bool(text),
                          help=USER_HELP if text else None, group=group, origin=Origin.CONFIG)]
    if home := default_home(user, home):
        found.append(Substitution(name, "environment", {"HOME": home, **(service.get("environment") or {})}))
    return found


def _pinned(name: str, service: dict[str, Any], assessment: Assessment) -> list[Substitution]:
    """Returns the substitutions that pin a started service to what the assessment of its image checked:
    the user, as numbers, the image by id unless it is built, and pull_policy never.
    """
    if assessment.kind is Kind.FALLBACK:
        found = _user(name, service, assessment.pinned_user, assessment.home,
                      verdict.instead_of_root(assessment), PINNED)
    else:  # the image's user, or the one its image section configures
        origin = Origin.IMAGE if assessment.kind is Kind.IMAGE else Origin.CONFIG
        found = [Substitution(name, "user", ids.format_user(assessment.pinned_user), group=PINNED,
                              origin=origin)]
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
