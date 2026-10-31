"""Messages to the person running dockscreen, on stderr.

Every message is one line that starts with PREFIX, so it can be told apart from what docker and compose
print. Text is escaped with printable(), because much of it quotes the untrusted project or image.
Command output that is meant as data (audit reports, harden patches, help) goes to stdout and is not
a message.

A line can start with a mark (Marked): a plain text symbol, coloured as docker colours its own when the
line goes to a terminal and NO_COLOR is not set. The line keeps its mark as an attribute, so the same
symbol can stand for different things in different colours.
"""

import os
import shutil
import sys
import textwrap

PREFIX = "[dockscreen]"
DOCKER_NOT_FOUND = "'docker' not found in PATH"


class Mark(str):
    """A symbol, and the ANSI colour a terminal shows it in, bold."""

    def __new__(cls, glyph, colour):
        mark = super().__new__(cls, glyph)
        mark.colour = colour
        return mark


class Marked(str):
    """`MARK text`, keeping the mark for colouring.

    help: an optional second part that says what to do about it, shown only in helpful mode
    (set_helpful). The line itself only states the facts, and its string value is just that.
    """

    def __new__(cls, mark, text, help=None):
        line = super().__new__(cls, f"{mark} {text}")
        line.mark, line.text, line.help = mark, text, help
        return line

    @property
    def _shown(self):
        """Returns the text, followed by the help if there is one and helpful mode is on."""
        return f"{self.text} - {self.help}" if self.help and _helpful else self.text


class Reason(str):
    """Why something is refused or failed, with an optional `help`: what to do about it."""

    def __new__(cls, text, help=None):
        reason = super().__new__(cls, text)
        reason.help = help
        return reason


def help_of(reason):
    """Returns the help of a Reason, or None for a plain string."""
    return getattr(reason, "help", None)


_helpful = False


def set_helpful(on):
    """Turns helpful mode on or off: whether messages show their help (--helpful, --verbose, audit)."""
    global _helpful
    _helpful = on


GREEN, YELLOW, RED, BLUE, CYAN = "32", "33", "31", "34", "36"
GOOD = Mark("\u25cf", GREEN)    # ● accepted as it is
WARN = Mark("\u25cf", YELLOW)   # ● allowed, but worth a look; also a change that can alter behaviour
BAD = Mark("\u25cf", RED)       # ● refused, or could not be checked
HINT = Mark("\u24d8", BLUE)     # ⓘ how to get past something
ROUTINE = Mark("\u25cf", CYAN)  # \u25cf changed by dockscreen, rarely matters
PASSED = Mark("\u2714", GREEN)  # ✔
REFUSED = Mark("\u2296", RED)   # ⊖
FAILED = Mark("\u2718", RED)    # ✘ could not look, as docker marks errors


# Report lines are wrapped to the terminal, but never wider than MAX_WIDTH, and not at all on a
# terminal narrower than MIN_WIDTH, or without one. A tab is TAB_WIDTH columns; continued lines line
# up with the text after the mark.
MAX_WIDTH, MIN_WIDTH, TAB_WIDTH = 120, 20, 8
CONTINUATION = "  "


def routine_change(text, help=None):
    """Builds a line about something dockscreen changes that rarely affects how the thing runs."""
    return Marked(ROUTINE, text, help)


def notable_change(text, help=None):
    """Builds a line about something dockscreen changes that can alter how the thing runs."""
    return Marked(WARN, text, help)


def notice(text):
    """Prints text to stderr as one dockscreen message: prefixed, escaped and with its mark painted."""
    print(f"{PREFIX} {_paint(text, sys.stderr)}", file=sys.stderr)


def out(text, indent=True):
    """Prints a line of a report to stdout, escaped and with its mark coloured.

    indent: print it after a tab, which sets the report apart from the [dockscreen] messages on stderr,
    wrapped to report_width() with the text lined up after the mark. Without it, the line is printed
    as it is, for output that is all one line (--brief).
    """
    if not indent:
        print(_paint(text, sys.stdout))
        return
    for line in _wrapped(text, report_width(), _wants_colour(sys.stdout)):
        print(f"\t{line}")


def report_width(fallback=0):
    """Returns the width to wrap report lines at: COLUMNS or the terminal's, at most MAX_WIDTH, or None
    (no wrapping) below MIN_WIDTH.

    fallback: the width when neither is known, as when the output goes to grep or less; 0 for no wrapping.
    """
    columns = shutil.get_terminal_size((fallback, 24)).columns
    return None if columns < MIN_WIDTH else min(columns, MAX_WIDTH)


def _wrapped(text, width, colour):
    """Splits text into escaped lines that fit width columns after a tab, never breaking a word.

    Continued lines line up under the text after the mark. width: None for one line; colour: whether
    to colour the mark.
    """
    lead = f"{text.mark} " if isinstance(text, Marked) else ""
    body = printable(text._shown if lead else text)
    if width is None:
        lines = [lead + body]
    else:
        lines = textwrap.wrap(lead + body, width=width - TAB_WIDTH, subsequent_indent=CONTINUATION,
                              break_long_words=False, break_on_hyphens=False) or [""]
    if lead and colour:  # coloured after wrapping, so the escape codes take up no width
        lines[0] = _coloured(text.mark) + lines[0][len(text.mark):]
    return lines


def _paint(line, stream):
    """Returns line escaped (printable), with its mark coloured if stream is a terminal that wants colour."""
    if not isinstance(line, Marked):
        return printable(line)
    mark = _coloured(line.mark) if _wants_colour(stream) else line.mark
    return f"{mark} {printable(line._shown)}"


def _coloured(mark):
    """Returns mark wrapped in the terminal escapes for its colour, bold."""
    return f"\x1b[1;{mark.colour}m{mark}\x1b[0m"  # bold, for all alike


def _wants_colour(stream):
    """Tells whether to colour what is written to stream: a terminal, without NO_COLOR or TERM=dumb."""
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def warning(text):
    """Prints text as a warning message (notice)."""
    notice(f"warning: {text}")


def report(problems):
    """Prints a refusal for each problem, with its help; returns whether there were none."""
    for problem in problems:
        notice(Marked(BAD, f"refusing: {problem}", help_of(problem)))
    return not problems


def refuse(problems):
    """Prints the problems as refusals (report) and returns exit status 1, even if there are none."""
    report(problems)
    return 1


def printable(text):
    """Returns str(text) as one line, with every character that is not printable escaped.

    Stops a config from forging output lines (newlines), rewriting the terminal
    (escape sequences) or reordering text (bidi overrides).
    """
    return "".join(c if c.isprintable() else _escape(c) for c in str(text))


def _escape(char):
    """Returns char as a backslash escape: \\xNN, \\uNNNN or \\UNNNNNNNN, by its code point."""
    code = ord(char)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def fatal(text):
    """Exits with status 1, printing text (escaped) as a dockscreen message."""
    sys.exit(f"{PREFIX} {printable(text)}")
