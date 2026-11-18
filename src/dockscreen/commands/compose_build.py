"""This module implements `docker compose build` and `bake`. Before compose builds the project, dockscreen
checks only the parts of this host that a build can reach.

Builds start no containers of the project. So dockscreen checks only the files and access that a build can
reach (projectscreening.check_build): build sources must be inside the project, and there may be no host
network and no `x-` keys, which `buildx bake` would read.
"""

from dockscreen.commands import helptext
from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.screen import projectscreening
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose build` or `bake` if the project's builds pass the checks. Returns 1 if they do
    not; otherwise docker replaces this process.

    Parameters:
    - parent_cli: the compose command line, with `build` or `bake` as its command; its lead_args are the
      compose options, which select the project
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd in ("build", "bake")
    global_args = parent_cli.lead_args
    if not Report.of(projectscreening.check_build(global_args, runtime)).show_screening():
        return 1
    runtime.docker.exec(["compose", *global_args, parent_cli.cmd, *parent_cli.args])


def help(name: str) -> helptext.HelpTopic:
    """Returns the help of the command name.

    Parameters:
    - name: the command, as the dispatcher knows it: build or bake
    """
    if name == "bake":
        return helptext.HelpTopic("dockscreen compose bake [OPTIONS] [SERVICE...]",
                                  "Build with bake, after checking what the builds can reach",
                                  (*helptext.BUILD_RULES,
                               "x- keys in build are refused, because bake reads x-bake."))
    assert name == "build"
    return helptext.HelpTopic("dockscreen compose build [OPTIONS] [SERVICE...]",
                              "Build services, after checking what the builds can reach",
                              helptext.BUILD_RULES)
