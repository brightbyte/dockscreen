"""Reading docker and compose command lines just far enough to find one thing in them.

None of these is a full parser: each knows which options take a value only from the set it is given,
and the callers are written so that a misreading refuses or changes nothing.
"""


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
