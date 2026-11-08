"""This module provides what every reader of docker and compose command lines uses: the names of dockscreen's
own options, which docker and compose never see, the CommandLine class, which splits a command line at its
command and holds it without them, and functions that find one thing in a command line.

Before the subcommand (main_commandline and CommandLine.subcommand take them out):
- --skip-screening runs the real thing with no checks and no defaults. After the subcommand it is
  not recognised, so docker or compose rejects it, which is the safe direction. The warning is
  printed every time and cannot be silenced, because the flag may have been copied into a script or
  an alias.
- --allow-me lets services and images run as the caller's own ids (see idrules), for compose. Docker's
  commands refuse it: `audit`, `create`, `exec` and `run` take --as-me, --as or --user instead.
- --helpful (or --verbose) adds the second part of messages that have one: why, and what it costs.
  The audit commands do that anyway. --verbose is taken here, not passed on, so that it does not
  make docker or compose noisy as well.
- --strict-screen treats the command line as untrusted too: what it asks for that a project or an
  image may not have (see Policy.check_container) is refused. `audit`, `run`, `create`, `start`,
  `restart` and `buildx bake` support it so far; everything else refuses to run with it, rather than
  ignore it.

After `audit`, for compose and docker alike: --brief prints only the verdict, in one line.

After `run` or `exec` (userargs and runargs replace them by `--user=uid:gid`):
- --as NAME: a local user by name, resolved on this host.
- --as-me: the caller's own ids.

The helpers are not full parsers: each knows which options take a value only from the set it is given,
and the callers are written so that a misreading refuses or changes nothing.
"""

from collections.abc import Collection, Sequence

from dockscreen.util import messages

SKIP_SCREENING = "--skip-screening"
ALLOW_ME = "--allow-me"
AS = "--as"
AS_ME = "--as-me"
STRICT_SCREEN = "--strict-screen"
# What --strict-screen is refused with before a command that does not support it.
STRICT_REFUSAL = (f"{STRICT_SCREEN} is only supported for audit, create, restart, run, start, buildx bake "
                  "and compose run so far")
# What --allow-me is refused with before a command that does not support it.
ALLOW_ME_REFUSAL = (f"{ALLOW_ME} is only supported for compose; for run, audit and create, choose the user "
                    f"after the command with {AS_ME}, {AS} NAME or --user UID:GID")
HELPFUL = "--helpful"
VERBOSE = "--verbose"
BRIEF = "--brief"
# dockscreen's own options before the docker command
OWN_OPTIONS = frozenset({SKIP_SCREENING, ALLOW_ME, STRICT_SCREEN, HELPFUL, VERBOSE})

AS_ME_MESSAGE = messages.Message(
    messages.BAD, "--as-me goes after run or exec, before the service",
    "for up, give --allow-me before the subcommand, and user: \"${UID}:${GID}\" to the services that should "
    "run as you")


def _split_argv(argv: Sequence[str], value_opts: Collection[str] = (), own_opts: Collection[str] = ()
               ) -> tuple[str | None, tuple[str, ...], tuple[str, ...], frozenset[str]]:
    """Splits argv at its command and returns (command, arguments after it, options before it, own options
    taken out). The command is None, and the arguments are empty, if argv has none before `--`.

    Only the own options before the command are taken out; those after it, and any after `--`, stay.

    Parameters:
    - argv: the arguments, in the form [options...] [command [arguments...]]
    - value_opts: the options before the command that take the next token as their value, which is then
      not the command
    - own_opts: dockscreen's own options, to take out of those before the command
    """
    taken: set[str] = set()
    kept: list[str] = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--":
            break
        if token in own_opts:
            taken.add(token)
            i += 1
        elif token in value_opts:
            kept += argv[i:i + 2]
            i += 2
        elif token.startswith("-"):
            kept.append(token)
            i += 1
        else:
            break
    rest = (*kept, *argv[i:])
    idx = _find_subcommand(rest, value_opts)
    if idx is None:
        return None, (), rest, frozenset(taken)
    return rest[idx], rest[idx + 1:], rest[:idx], frozenset(taken)


class CommandLine:
    """Record of one level of a docker command line, `docker run …` or the `up …` of `docker compose up …`,
    split at its command, with dockscreen's own options before the command taken out. It holds the options
    before the command, the command and the arguments after it, which dockscreen options were given, and
    what came before this level.

    Instances come from main_commandline, for the docker command line, and from subcommand, for the
    command line of a command that has commands of its own (compose, buildx, container). Nothing changes
    their attributes afterwards, though nothing enforces that.

    Attributes:
    - cmd: the command, or None if there is none
    - lead_args: the options before the command, at this level only; all of argv if there is no command
    - args: the arguments after the command; empty if there is none
    - own_args: dockscreen's own options that were given, at this level or one before it; none of them is
      in argv
    - prefix: the docker command line before this level, up to and including the command it belongs to
      (`compose` for compose's); empty for docker's own
    """

    def __init__(self, cmd: str | None, args: Collection[str], lead: Collection[str] = (),
                 own_args: Collection[str] = (), prefix: Collection[str] = ()) -> None:
        """Holds a command line that is already split.

        Parameters:
        - cmd: the command; None for none
        - args: the arguments after the command
        - lead: the options before the command
        - own_args: dockscreen's own options that were given
        - prefix: the docker command line before this level (prefix in the class docstring)
        """
        self.cmd = cmd
        self.args = tuple(args)
        self.lead_args = tuple(lead)
        self.own_args = frozenset(own_args)
        self.prefix = tuple(prefix)

    def has_own(self, option: str) -> bool:
        """Tells whether option, one of dockscreen's own, was given."""
        return option in self.own_args

    @property
    def argv(self) -> list[str]:
        """Returns this level of the command line as docker or compose gets it: the options before the
        command, the command, and the arguments after it, without dockscreen's own options. The prefix is
        not part of it.
        """
        return [*self.lead_args, *([self.cmd] if self.cmd is not None else []), *self.args]

    @property
    def full_argv(self) -> list[str]:
        """Returns the whole docker command line: the prefix, then argv."""
        return [*self.prefix, *self.argv]

    @property
    def global_args(self) -> list[str]:
        """Returns the docker command line up to the command, composed from the prefix and
        lead before the command.

        This is meant to be used when building commands. To read an option, look at the
        lead_args of its own level: what an option means, and whether it takes a value,
        depends on the level.
        """
        return [*self.prefix, *self.lead_args]

    @property
    def skip_screening(self) -> bool:
        """Tells whether --skip-screening was given."""
        return self.has_own(SKIP_SCREENING)

    @property
    def allow_me(self) -> bool:
        """Tells whether --allow-me was given."""
        return self.has_own(ALLOW_ME)

    @property
    def as_me(self) -> bool:
        """Tells whether --as-me was given before the command, where it does not belong."""
        return self.has_own(AS_ME)

    @property
    def strict(self) -> bool:
        """Tells whether --strict-screen was given."""
        return self.has_own(STRICT_SCREEN)

    @property
    def helpful(self) -> bool:
        """Tells whether --helpful or --verbose was given."""
        return self.has_own(HELPFUL) or self.has_own(VERBOSE)

    def subcommand(self, value_opts: Collection[str] = (), own_opts: Collection[str] = (),
                   inherit_lead: bool = False) -> "CommandLine":
        """Returns the command line of the command, read from the arguments after it: `up -d` for the
        `compose -f a.yml up -d` of `docker compose -f a.yml up -d`.

        It keeps the dockscreen options given here, and its prefix is this one's up to and including the
        command. With inherit_lead, it takes this one's place instead: its lead starts with this one's, its
        prefix is this one's, and this command is dropped. That is only right where the subcommand on its
        own means the same, as `run` does for `container run`.

        Parameters:
        - value_opts: the command's options that take the next token as their value
        - own_opts: dockscreen's own options, to take out of those before its command
        - inherit_lead: whether the subcommand replaces this command, keeping the options before it
        """
        cmd, args, lead, taken = _split_argv(self.args, value_opts, own_opts)
        if inherit_lead:
            return CommandLine(cmd, args, [*self.lead_args, *lead], self.own_args | taken, self.prefix)
        prefix = [*self.prefix, *self.lead_args, *([self.cmd] if self.cmd is not None else [])]
        return CommandLine(cmd, args, lead, self.own_args | taken, prefix)


def main_commandline(argv: Sequence[str], value_opts: Collection[str] = (),
                     own_opts: Collection[str] = ()) -> CommandLine:
    """Returns the CommandLine of a docker command line.

    Parameters:
    - argv: the arguments, without the program
    - value_opts: docker's options that take the next token as their value, which is then not the command
    - own_opts: dockscreen's own options, to take out of those before the command
    """
    cmd, args, lead, taken = _split_argv(argv, value_opts, own_opts)
    return CommandLine(cmd, args, lead, taken)


def banner() -> None:
    """Warns on stderr that screening is turned off for this command."""
    messages.warning(f"{SKIP_SCREENING} given: screening is disabled.")
    messages.warning("nothing in this command is checked, and no defaults are added.")


def _find_subcommand(argv: Sequence[str], value_opts: Collection[str]) -> int | None:
    """Returns the index of the first argument that is not an option or an option's value, or None if
    there is none before `--`.

    Parameters:
    - argv: the arguments
    - value_opts: the options that take a value
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


def option_values(args: Sequence[str], long_name: str, short_name: str | None) -> list[str]:
    """Returns every value given for the option, in order, in `--opt v`, `--opt=v`, `-o v`, `-ov` and `-o=v`
    forms, read as compose's flag parser reads them.

    Parameters:
    - args: the arguments
    - long_name: the option's long name, with its dashes
    - short_name: its short name, with its dash; None if it has none
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


def option_value(args: Sequence[str], name: str) -> str | None:
    """Returns the value of the first `--name value` or `--name=value` before any `--`, or None.

    Parameters:
    - args: the arguments
    - name: the option, with its dashes
    """
    for i, arg in enumerate(args):
        if arg == "--":
            break
        if arg.startswith(name + "="):
            return arg.partition("=")[2]
        if arg == name and i + 1 < len(args):
            return args[i + 1]
    return None


def strip_options(args: Sequence[str], names: Collection[str]) -> list[str]:
    """Returns args without the given options and their values, in `--opt v`, `--opt=v` and `-ov` forms.

    Parameters:
    - args: the arguments
    - names: options that take a value, long and short
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


def positionals(args: Sequence[str], long_values: Collection[str],
                short_values: Collection[str]) -> list[str]:
    """Returns the arguments that are not options or option values, and everything after `--`.

    Parameters:
    - args: the arguments
    - long_values: long options that take a value
    - short_values: letters of short options that do, which take the next argument when they end a cluster
    """
    found: list[str] = []
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
