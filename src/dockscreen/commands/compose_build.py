"""This module implements `docker compose build` and `bake`, checking only what a build can reach before
compose builds the project.

Builds start no containers of the project, so only what a build can reach is checked
(projectscreening.check_build): build sources inside the project, no host network, no `x-` keys that
`buildx bake` would read.
"""

from dockscreen.commands import helptext
from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.screen import projectscreening
from dockscreen.util import commandline


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker compose build` or `bake` if the project's builds pass the checks; returns 1 if they do
    not, otherwise docker replaces this process.

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
