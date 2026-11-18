"""This module provides the steps that compose up, create and run share. They have the project screened, print
the findings, and run compose as a child process on the config that the policy checked. Compose runs while the
generated file that it reads exists (projectscreening).
"""

from collections.abc import Sequence

from dockscreen.host.docker import DockerError
from dockscreen.host.runtime import Runtime
from dockscreen.policy import userdecisionview
from dockscreen.policy.notice import Notice
from dockscreen.policy.report import Report
from dockscreen.screen import inspect, projectscreening, userargs
from dockscreen.screen.screener import Screener
from dockscreen.util import messages


def check_and_run(global_args: list[str], sub: str, user_args: userargs.UserArgs[str], runtime: Runtime,
                  is_me_allowed: bool = False, is_strict: bool = False,
                  notices: Sequence[Notice] = ()) -> int:
    """Runs `docker compose global_args sub`, with the arguments of user_args, if the project passes the
    checks. sub is a subcommand that starts containers, and global_args select the project.

    Returns the exit status: 1 if the policy refuses the project or its images, or if dockscreen cannot check
    them; otherwise the status of the subcommand. First, this acquires the images of the services that set no
    user, following the project's pull policy, and has the policy decide on their users (serviceinfo,
    imageusers). The config that runs is the one that the policy checked, with those decisions applied.

    Parameters:
    - global_args: the compose options before the subcommand, which select the project
    - sub: the subcommand
    - user_args: the subcommand's arguments, with the user the command line chose, resolved
      (userscreening.screen_user_options)
    - runtime: the Runtime of the command
    - is_me_allowed: the invoking user gave --allow-me, so the policy allows their own ids
    - is_strict: the user gave --strict-screen. The policy then judges the service as `run`'s options change
      it (runoptions), with the command line untrusted. Otherwise compose gets those options as given, as
      docker does for `docker run`.
    - notices: the notices from resolving the user that the command line chose
      (userscreening.screen_user_options); they are printed with the project's notices
    """
    try:
        loaded_project = projectscreening.load_project(global_args, runtime)
    except DockerError as e:
        Report.failure(e).show_screening()
        return 1
    except inspect.ProjectRefusal as e:
        Report.of(e.findings).show_screening()
        return 1
    except ValueError as e:
        Report.refusal(str(e)).show_screening()
        return 1

    screener = Screener(runtime, is_me_allowed)
    project_policy = screener.policy(loaded_project.directory)
    project_notices = [*notices, *projectscreening.surroundings(loaded_project, screener),
                       userdecisionview.root_default_notice(project_policy.default_user),
                       *loaded_project.hardening.notices()]
    check_result = projectscreening.check(loaded_project, screener)
    if isinstance(check_result, Report):
        check_result.show_screening()
        return 1
    cleared_project = check_result
    with loaded_project.generated_files(screener.docker.binary) as command:
        decisions = projectscreening.decide(cleared_project, screener, command, user_args.args,
                                            _chosen_services(user_args))
        finish_result = projectscreening.finish(cleared_project, decisions, screener, user_args, is_strict)
        if isinstance(finish_result, Report):
            finish_result.show_screening()
            return 1
        runnable_project = finish_result
        for notice in [*project_notices, *decisions.notices()]:
            if notice:
                messages.print_notice(notice)
        runnable_project.report.show_screening()
        return screener.docker.run_child([*command(runnable_project.project.definition), sub,
                                          *user_args.args])


def _chosen_services(user_args: userargs.UserArgs[str]) -> frozenset[str]:
    """Returns the services whose user the command line chooses: `run -u uid:gid` or `run --as NAME`."""
    if user_args.users.is_user_chosen and user_args.service:
        return frozenset({user_args.service})
    return frozenset()
