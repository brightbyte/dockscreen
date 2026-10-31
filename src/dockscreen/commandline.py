"""Reading docker and compose command lines: dockscreen's own options, which docker and compose never
see, and helpers that find one thing in a command line.

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

The helpers are not full parsers: each knows which options take a value only from the set it is given,
and the callers are written so that a misreading refuses or changes nothing.
"""

from dockscreen import messages

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
        self.idx = find_subcommand(self.argv, value_opts)

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


def find_subcommand(argv, value_opts):
    """Returns the index of the first argument that is not an option or an option's value, or None if
    there is none before `--`.

    value_opts: the options that take a value.
    """
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            return None
        if token in value_opts:
            i += 2
        elif token.startswith("-"):
            i += 1
        else:
            return i
    return None


def option_values(args, long_name, short_name):
    """Returns every value given for the option, in order, in `--opt v`, `--opt=v`, `-o v`, `-ov` and `-o=v`
    forms, read as compose's flag parser reads them. short_name may be None.
    """
    values = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in (long_name, short_name) and i + 1 < len(args):
            values.append(args[i + 1])
            i += 1
        elif token.startswith(long_name + "="):
            values.append(token[len(long_name) + 1:])
        elif short_name and token.startswith(short_name) and not token.startswith("--") and len(token) > 2:
            values.append(token[3:] if token[2] == "=" else token[2:])
        i += 1
    return values


def option_value(args, name):
    """Returns the value of the first `--name value` or `--name=value` before any `--`, or None."""
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg.startswith(name + "="):
            return arg.partition("=")[2]
        if arg == name and i + 1 < len(args):
            return args[i + 1]
    return None


def strip_options(args, names):
    """Returns args without the given options and their values, in `--opt v`, `--opt=v` and `-ov` forms.

    names: options that take a value, long and short.
    """
    kept = []
    i = 0
    while i < len(args):
        token = args[i]
        if token in names:
            i += 2
        # compose reads `-fvalue` and `-f=value` as -f with a value, so a short name matches a prefix
        elif any(token.startswith(n + "=") for n in names if n.startswith("--")) \
                or any(token.startswith(n) for n in names if not n.startswith("--")):
            i += 1
        else:
            kept.append(token)
            i += 1
    return kept


def positionals(args, long_values, short_values):
    """Returns the arguments that are not options or option values, and everything after `--`.

    long_values: long options that take a value; short_values: letters of short options that do, which
    take the next argument when they end a cluster.
    """
    found = []
    i = 0
    while i < len(args):
        token = args[i]
        if token == "--":
            found += args[i + 1:]
            break
        if token.startswith("--"):
            i += 1 if "=" in token or token not in long_values else 2
        elif token.startswith("-") and token != "-":
            i += 2 if token[-1] in short_values else 1
        else:
            found.append(token)
            i += 1
    return found
