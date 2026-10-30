"""Running docker compose from the config we checked, not from the files it would find itself.

The resolved config is hardened, checked, written to a private temporary file
(`config` prints a literal `$` as `$$`, so compose reads the file back to the same values)
and handed to compose as its only file, together with the project directory and
name it came from. What was checked is then exactly what runs: no second
reading of the project's files, no discovery rules to mirror. composeimages.prepare
asks compose for the config of the generated file and refuses if it differs from
what was checked. The price is that
compose runs as a child process (so the file can be removed afterwards) and
shows the temporary file as its config file.
"""

import contextlib
import itertools
import json
import os
import tempfile
from typing import NamedTuple

from dockscreen import argscan, hostusers, imagedecision, messages, policy, verdict
from dockscreen.compose import composeargs, composeimages, hardening, screen, shellenv
from dockscreen.dockerclient import DockerNotFound

# Options that select the files and the project; ours replace them.
REPLACED_OPTIONS = ("--file", "-f", "--project-directory", "--project-name", "-p")


class Project(NamedTuple):
    """A compose project as dockscreen runs it: hardened, and what the policy needs to check it."""
    global_args: list          # the compose options that select it
    directory: str
    hardened: dict             # the resolved config with hardening applied
    additions: list            # what hardening added (hardening.Addition)
    ctx: policy.Context        # with nothing vetted yet
    image_ctx: imagedecision.Context  # to pull, build, decide and run with
    remote: bool               # the daemon may not be this host's own
    docker_binary: str         # the real docker, to run `docker compose` with
    runtime: object = None     # runtime.Runtime it was loaded with
    allow_me: bool = False

    def static_ctx(self):
        """Returns ctx for the checks before any image is looked at, which leave unset users to later."""
        return self.ctx._replace(vetted=composeimages.unset_user_services(self.hardened))

    def problems(self):
        """Returns what is refused before any image is looked at; empty if nothing is."""
        problems = policy.check_config(self.hardened, self.static_ctx())
        if not self.hardened.get("name"):
            problems.append("config has no project name")
        if self.remote:
            problems.append(screen.REMOTE_MESSAGE)
        elif not problems and not screen.names_project(self.global_args, self.runtime.env):
            problems += screen.name_conflicts(self.hardened["name"], self.directory,
                                              self.image_ctx.docker)
        return problems

    def final_ctx(self, prepared, vetted):
        """Returns ctx for the config that will run, with vetted as the services pinned to an accepted
        image, and image sections only where prepared proved them.
        """
        verified = prepared.verified or {}
        return screen.context(self.directory, self.runtime, self.allow_me, verified)._replace(vetted=vetted)

    def generated(self):
        """Returns _generated() for this project."""
        return _generated(self.global_args, self.directory, self.docker_binary)


def load_project(global_args, runtime, allow_me, image_ctx=None):
    """Loads the project global_args select, hardened.

    Raises screen.ScreenError or ValueError if it cannot be inspected.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    image_ctx: what to pull, build, decide and run with; image_context() if not given.
    """
    config, directory = screen.inspect(global_args, runtime)
    hardened, additions = hardening.apply(config, runtime.accounts)
    image_ctx = (image_ctx or image_context(runtime, allow_me))._replace(project_dir=directory)
    remote = screen.is_remote(global_args, runtime.env, image_ctx.docker)
    ctx = screen.context(directory, runtime, allow_me)
    return Project(global_args, directory, hardened, additions, ctx, image_ctx, remote, runtime.docker.binary,
                   runtime, allow_me)


def run(argv, idx, runtime, image_ctx=None, allow_me=False):
    """Runs argv[idx:], a subcommand that starts containers, on the project if it passes the checks.

    Returns the exit status: 1 if the project or its images are refused or cannot be checked, else the
    subcommand's. The images of services that set no user are acquired first, by the project's pull policy,
    and decided on (composeimages); the config that runs is the one that was checked, with the result.
    allow_me: --allow-me was given, so the caller's own ids are allowed.
    """
    try:
        parsed = _command_line(argv[idx], argv[idx + 1:], runtime)
        project = load_project(argv[:idx], runtime, allow_me, image_ctx)
        problems = project.problems()
    except (screen.InspectError, DockerNotFound) as e:
        verdict.screened([str(e)], failed=True)
        return 1
    except (screen.ScreenError, hostusers.UserError, ValueError) as e:
        problems = [str(e)]
    if problems:
        verdict.screened(problems)
        return 1

    hardened, image_ctx = project.hardened, project.image_ctx
    lines = [*parsed.notices, *screen.mount_dir_warnings(runtime),
             imagedecision.root_default_notice(image_ctx), *hardening.describe(project.additions)]
    lines += shellenv.describe(hardened, runtime.env)
    with project.generated() as command:
        prepared = composeimages.prepare(command(hardened), hardened, parsed.args, image_ctx, _chosen(parsed))
        if prepared.problems:
            verdict.screened(prepared.problems, failed=prepared.failed)
            return 1
        final, vetted = prepared.finalize()
        problems = policy.check_config(final, project.final_ctx(prepared, vetted))  # what will run
        if problems:
            verdict.screened(problems)
            return 1
        for line in [*lines, *prepared.notices()]:
            if line:
                messages.notice(line)
        verdict.screened([])
        return image_ctx.docker.run_child([*command(final), argv[idx], *parsed.args])


def _command_line(subcommand, args, runtime):
    """Parses args for `run` as composeargs does, with --as resolved; other subcommands keep them as
    they are.

    Raises hostusers.UserError for a user that is not numeric `uid:gid`, or an unknown --as name.
    """
    if subcommand != "run":
        return composeargs.Parsed(None, False, args, [])
    return composeargs.parse("run", args, runtime.me, runtime.accounts)


def _chosen(parsed):
    """Returns the services whose user the command line chooses: `run -u uid:gid` or `run --as NAME`."""
    return frozenset({parsed.service}) if parsed.user_given and parsed.service else frozenset()


@contextlib.contextmanager
def _generated(global_args, project_dir, docker_binary):
    """Provides a private temporary directory for generated configs, and yields command(config).

    command writes config there and returns the `docker compose` command line on it alone, with the project
    directory and name pinned, ready for a subcommand to be appended. Everything is removed afterwards.
    """
    counter = itertools.count()
    with tempfile.TemporaryDirectory(prefix="dockscreen-") as directory:
        def command(config):
            path = os.path.join(directory, f"compose-{next(counter)}.yaml")
            with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as f:
                json.dump(config, f)  # JSON is YAML
            return [
                docker_binary, "compose", *argscan.strip_options(global_args, REPLACED_OPTIONS),
                "-f", path, "--project-directory", project_dir, "--project-name", config["name"],
            ]
        yield command


def image_context(runtime, allow_me=False):
    """Returns the imagedecision.Context to pull, build, decide and run with."""
    return imagedecision.Context(runtime.docker, runtime.rules(allow_me), runtime)
