"""This module implements `docker buildx bake`, checking what the project's bake files let the builds reach
on this host.

Bake reads files the project controls (docker-bake.hcl, compose files with `x-bake`), as `compose build`
does, so the same things are refused: build sources outside the project, host networking, the SSH
agent. Bake adds ways to write to the host (`output`, `cache-to`) and to read files and variables
(`secret`). What would be built is screened before (bakescreening).
"""

from collections.abc import Collection

from dockscreen.host.runtime import Runtime
from dockscreen.policy.report import Report
from dockscreen.screen import bakescreening
from dockscreen.screen.screener import Screener
from dockscreen.util import commandline

NOT_SCREENED = {"--print", "--help", "-h"}  # builds nothing


def _wants_screening(args: Collection[str]) -> bool:
    """Tells whether `bake` with these arguments builds, and so needs screening."""
    return not NOT_SCREENED & set(args)


def gate(parent_cli: commandline.CommandLine, runtime: Runtime) -> int:
    """Runs `docker buildx bake` if the definition it would build passes the policy for builds; returns 1 if
    it does not, otherwise docker replaces this process. With --print or --help it builds nothing, and runs
    unchecked.

    Parameters:
    - parent_cli: buildx's part of the command line, with `bake` as its command
    - runtime: the Runtime of the command
    """
    assert parent_cli.cmd == "bake"
    if _wants_screening(parent_cli.args):
        bake_policy = Screener(runtime).policy(runtime.cwd)
        refusals = bakescreening.check(runtime.docker, parent_cli, bake_policy, runtime.cwd)
        if not Report.of(refusals).show_screening():
            return 1
    runtime.docker.exec(parent_cli.full_argv)
