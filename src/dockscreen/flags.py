"""dockscreen's own options, which docker and compose never see.

Before the subcommand (CommandLine takes them out):
- --skip-screening runs the real thing with no checks and no defaults. After the subcommand it is
  not recognised, so docker or compose rejects it, which is the safe direction. The warning is
  printed every time and cannot be silenced, because the flag may have been copied into a script or
  an alias.
- --allow-me lets services and images run as the caller's own ids (see idrules).
- --helpful (or --verbose) adds the second part of messages that have one: why, and what it costs.
  The audit commands do that anyway. --verbose is taken here, not passed on, so that it does not
  make docker or compose noisy as well.
- --strict-screen treats the command line as untrusted too: what it asks for that a project or an
  image may not have (see runpolicy) is refused. Only `audit` supports it so far; everything else
  refuses to run with it, rather than ignore it.

After `audit`, for compose and docker alike: --brief prints only the verdict, in one line.

After `run` or `exec` (userargs and runargs replace them by `--user=uid:gid`):
- --as NAME: a local user by name, resolved on this host.
- --as-me: the caller's own ids; with `docker run` it implies --allow-me.
"""

from dockscreen import argscan, messages

SKIP_SCREENING = "--skip-screening"
ALLOW_ME = "--allow-me"
AS = "--as"
AS_ME = "--as-me"
STRICT_SCREEN = "--strict-screen"
HELPFUL = "--helpful"
VERBOSE = "--verbose"
BRIEF = "--brief"
AS_ME_MESSAGE = messages.Marked(
    messages.BAD, "--as-me goes after run or exec, before the service",
    "for up, give --allow-me before the subcommand, and user: \"${UID}:${GID}\" to the services that should "
    "run as you")


class CommandLine:
    """A docker or docker compose command line with dockscreen's own options before the command taken out,
    what those asked for, and where the command is.

    argv: the command line as docker or compose gets it; idx: the index of the command in it, or None.
    """

    def __init__(self, argv, value_opts, own, given=()):
        """Reads argv. value_opts: the options that take the next token as their value, which is then not the
        command; own: the options of ours to take out; given: options of ours given before, on the docker
        command line that this one follows.
        """
        self.value_opts = value_opts
        self.given = frozenset(given)
        kept, i = [], 0
        while i < len(argv):
            token = argv[i]
            if token == "--":
                break
            if token in own:
                self.given |= {token}
                i += 1
            elif token in value_opts:
                kept += argv[i:i + 2]
                i += 2
            elif token.startswith("-"):
                kept.append(token)
                i += 1
            else:
                break
        self.argv = [*kept, *argv[i:]]
        self.idx = argscan.find_subcommand(self.argv, value_opts)

    def has(self, option):
        """Tells whether option, one of ours, was given."""
        return option in self.given

    @property
    def skip_screening(self):
        """Tells whether --skip-screening was given."""
        return self.has(SKIP_SCREENING)

    @property
    def allow_me(self):
        """Tells whether --allow-me was given."""
        return self.has(ALLOW_ME)

    @property
    def as_me(self):
        """Tells whether --as-me was given before the command, where it does not belong."""
        return self.has(AS_ME)

    @property
    def strict(self):
        """Tells whether --strict-screen was given."""
        return self.has(STRICT_SCREEN)

    @property
    def helpful(self):
        """Tells whether --helpful or --verbose was given."""
        return self.has(HELPFUL) or self.has(VERBOSE)

    @property
    def sub(self):
        """Returns the command (the first argument that is not an option or an option's value), or None."""
        return None if self.idx is None else self.argv[self.idx]

    @property
    def global_args(self):
        """Returns the options before the command."""
        return self.argv if self.idx is None else self.argv[:self.idx]

    @property
    def args(self):
        """Returns the arguments after the command."""
        return [] if self.idx is None else self.argv[self.idx + 1:]


def banner():
    """Warns on stderr that screening is turned off for this command."""
    messages.warning(f"{SKIP_SCREENING} given: screening is disabled.")
    messages.warning("nothing in this command is checked, and no defaults are added.")
