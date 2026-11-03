"""This module provides functions for printing messages to the person running dockscreen, on stderr, and for
escaping the untrusted text they quote, so that it cannot pass for anything else.

Every message is one line that starts with PREFIX, so it can be told apart from what docker and compose
print. Text is escaped with printable(), because much of it quotes the untrusted project or image.
Only what docker printed about a failure (a reason's output) keeps its line breaks: it follows the
message on lines indented past PREFIX, each escaped, so none of them can pass for a message.
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
from typing import NoReturn, Self, TextIO

PREFIX = "[dockscreen]"
DOCKER_NOT_FOUND = "'docker' not found in PATH"


class Mark(str):
    """Value object for a symbol that starts a line, with the ANSI colour a terminal shows it in, bold. It is
    the symbol as a string, and holds the colour.

    - colour: the ANSI colour code

    The str base does not protect the colour, so nothing changes it after construction.
    """

    colour: str

    def __new__(cls, glyph: str, colour: str) -> Self:
        mark = super().__new__(cls, glyph)
        mark.colour = colour
        return mark


class Marked(str):
    """Value object for a message line that starts with a mark, which is kept apart from the text for
    colouring. Its string value is the text, without the mark, which only printing adds; the line only states
    the facts. It holds the mark, the text, what to do about it and what docker printed about it.

    - mark: the Mark
    - text: the text
    - help: what to do about it, shown only in helpful mode (set_helpful), or None
    - output: what docker printed about it, shown after it (notice), or None

    The str base does not protect these attributes, so nothing changes them after construction.
    """

    mark: Mark
    text: str
    help: str | None
    output: str | None

    def __new__(cls, mark: Mark, text: str, help: str | None = None, output: str | None = None) -> Self:
        line = super().__new__(cls, text)
        line.mark, line.text, line.help, line.output = mark, text, help, output
        return line

    @property
    def shown(self) -> str:
        """Returns the text, followed by the help if there is one and helpful mode is on (with_help)."""
        return with_help(self.text, self.help)


def with_help(text: str, help: str | None) -> str:
    """Returns text followed by help, if there is help and helpful mode is on (set_helpful)."""
    return f"{text} - {help}" if help and _helpful else text


def help_of(text: object) -> str | None:
    """Returns the help that comes with text (a Marked line, or a finding), or None for a plain string."""
    return getattr(text, "help", None)


def output_of(text: object) -> str | None:
    """Returns what docker printed that comes with text (a Marked line, a finding, or an error that carries
    an `output`), or None for a plain string.
    """
    return getattr(text, "output", None) or None


def with_output(text: object) -> str:
    """Returns text followed by its output (output_of), as one text: for where it has to fit on one line."""
    output = output_of(text)
    return f"{text}: {output}" if output else str(text)


_helpful = False


def set_helpful(on: bool) -> None:
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
# Where the lines of a message's output start: past PREFIX and a mark, so that none starts like a message.
OUTPUT_INDENT = " " * (len(PREFIX) + 1) + "  "


def notice(text: object) -> None:
    """Prints text to stderr as one dockscreen message: prefixed, escaped and with its mark painted.

    The output of a Marked line or a finding follows, each of its lines escaped and indented by OUTPUT_INDENT.
    """
    print(f"{PREFIX} {_paint(text, sys.stderr)}", file=sys.stderr)
    for line in (output_of(text) or "").splitlines():
        print(f"{OUTPUT_INDENT}{printable(line)}", file=sys.stderr)


def out(text: str, indent: bool = True) -> None:
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


def report_width(fallback: int = 0) -> int | None:
    """Returns the width to wrap report lines at: COLUMNS or the terminal's, at most MAX_WIDTH, or None
    (no wrapping) below MIN_WIDTH.

    fallback: the width when neither is known, as when the output goes to grep or less; 0 for no wrapping.
    """
    columns = shutil.get_terminal_size((fallback, 24)).columns
    return None if columns < MIN_WIDTH else min(columns, MAX_WIDTH)


def _wrapped(text: str, width: int | None, colour: bool) -> list[str]:
    """Splits text into escaped lines that fit width columns after a tab, never breaking a word.

    Continued lines line up under the text after the mark. width: None for one line; colour: whether
    to colour the mark.
    """
    if isinstance(text, Marked):
        lead, body = f"{text.mark} ", printable(text.shown)
    else:
        lead, body = "", printable(text)
    if width is None:
        lines = [lead + body]
    else:
        lines = textwrap.wrap(lead + body, width=width - TAB_WIDTH, subsequent_indent=CONTINUATION,
                              break_long_words=False, break_on_hyphens=False) or [""]
    if isinstance(text, Marked) and colour:  # coloured after wrapping, so the escape codes take up no width
        lines[0] = _coloured(text.mark) + lines[0][len(text.mark):]
    return lines


def _paint(line: object, stream: TextIO) -> str:
    """Returns line escaped (printable), with its mark coloured if stream is a terminal that wants colour."""
    if not isinstance(line, Marked):
        return printable(line)
    mark = _coloured(line.mark) if _wants_colour(stream) else line.mark
    return f"{mark} {printable(line.shown)}"


def _coloured(mark: Mark) -> str:
    """Returns mark wrapped in the terminal escapes for its colour, bold."""
    return f"\x1b[1;{mark.colour}m{mark}\x1b[0m"  # bold, for all alike


def _wants_colour(stream: TextIO) -> bool:
    """Tells whether to colour what is written to stream: a terminal, without NO_COLOR or TERM=dumb."""
    if "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def warning(text: str) -> None:
    """Prints text as a warning message (notice)."""
    notice(f"warning: {text}")


def printable(text: object) -> str:
    """Returns str(text) as one line, with every character that is not printable escaped.

    Stops a config from forging output lines (newlines), rewriting the terminal
    (escape sequences) or reordering text (bidi overrides).
    """
    return "".join(c if c.isprintable() else _escape(c) for c in str(text))


def _escape(char: str) -> str:
    """Returns char as a backslash escape: \\xNN, \\uNNNN or \\UNNNNNNNN, by its code point."""
    code = ord(char)
    if code < 0x100:
        return f"\\x{code:02x}"
    return f"\\u{code:04x}" if code <= 0xFFFF else f"\\U{code:08x}"


def fatal(text: object) -> NoReturn:
    """Exits with status 1, printing text (escaped) as a dockscreen message."""
    sys.exit(f"{PREFIX} {printable(text)}")
