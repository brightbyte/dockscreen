"""This module provides functions for showing the help for dockscreen and the commands it audits or adds, laid
out like docker's own.

An overview lists dockscreen's options and the commands it audits or adds; a topic covers one command.
Docker's (or compose's) own help for the same thing follows ours, except for commands that only dockscreen
has. The help wraps text to the width of the audit report (messages.report_width). As in docker's help, option
and command descriptions wrap under their own column.
"""

import textwrap
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import NamedTuple

from dockscreen.util import commandline, messages

HELP_FALLBACK_WIDTH = 80


class HelpOption(NamedTuple):
    """Private helper that holds one option dockscreen adds to a command, as a help page lists it."""
    long: str
    text: str
    short: str = ""
    value: str = ""  # what the option takes, as docker names it: string, list, ...

    def _left_column(self) -> str:
        """Returns the option's left column in the help: its short and long name and its value."""
        short = f"-{self.short}, " if self.short else "    "
        return f"  {short}{self.long}" + (f" {self.value}" if self.value else "")


class HelpTopic(NamedTuple):
    """Record of the help page for one command, for showing it laid out like docker's own. It holds the
    command's usage and summary, notes on dockscreen's handling of the command, and dockscreen's own options
    for it.

    Attributes:
    - usage: the usage line
    - summary: one line, also in the overview
    - aliases: the other names of the command
    - notes: notes on dockscreen's handling of the command: paragraphs, and list items starting with "- "
    - options: dockscreen's own options for the command
    - has_docker_help: whether docker (or compose) has its own help for the command, which follows ours
    """
    usage: str
    summary: str
    notes: tuple = ()
    options: tuple = ()
    aliases: tuple = ()
    has_docker_help: bool = True


USER_OPTIONS = (
    HelpOption(commandline.AS_OPTION, "Run as the local user NAME, resolved on this host", value="string"),
    HelpOption(commandline.AS_ME_OPTION, "Run as yourself"),
    HelpOption("--user", "Numeric UID:GID only; --as is for names", short="u", value="string"),
)
DEFAULTS = ("dockscreen adds --cap-drop=ALL and --security-opt=no-new-privileges:true before your options, "
            "which can override them.")
IMAGE_RULES = (
    "- an image that would run as root runs as the default user instead (the nobody user unless configured)",
    ("- dockscreen denies an image user that is an account of this host, or, with mounts, an id outside the "
     "nobody range"),
    "- an image runs as the user that the config file sets for the image, for its project or for every image",
    "- dockscreen passes the user to docker as numbers, so the image's passwd file cannot change it",
)
VERDICT = "The last line dockscreen prints is the verdict: ✔ audit passed, ⊖ denied by audit, or " \
          "✘ audit failed."

DOCKER_OPTIONS = (
    HelpOption(commandline.HELPFUL_OPTION,
               "Also show advice on each message (also --verbose, which is not passed on)"),
    HelpOption(commandline.SKIP_SCREENING_OPTION, "Turn all checks off; dockscreen warns every time"),
    HelpOption(commandline.STRICT_SCREEN_OPTION,
               "For audit, run, create, start, restart, buildx bake and compose run: also deny the "
               "command line's requests that a project or image may not make"),
)
COMPOSE_OPTIONS = (
    HelpOption(commandline.ALLOW_ME_OPTION, "Allow services to run as you"),
    HelpOption(commandline.HELPFUL_OPTION,
               "Also show advice on each message (also --verbose, which is not passed on)"),
    HelpOption(commandline.SKIP_SCREENING_OPTION, "Turn all checks off; dockscreen warns every time"),
)

SCREENED_COMPOSE = (
    "dockscreen audits the project first, and runs it from the config it checked:",
    "- bind mounts and files only from the project directory or the configured mount_dirs",
    "- no privileges: privileged, cap_add, devices, host namespaces, other security options",
    "- users the project or its images choose must pass the id rules; dockscreen pulls images first",
    "- cap_drop: [ALL] and no-new-privileges added where they are missing",
    VERDICT,
)
BUILD_RULES = (("Builds may not read outside the project, use the host network, run privileged or forward "
                "your SSH agent."), VERDICT)
BRIEF_HELP = HelpOption(commandline.BRIEF_OPTION, "Print only the verdict, in one line")


def command_topic(name: str, function: Callable[..., object], aliases: Sequence[str] = (),
                  options: Sequence[HelpOption] = ()) -> HelpTopic:
    """Returns the HelpTopic of one of dockscreen's own compose commands, made from the docstring of function.

    The first line becomes the summary, and each further paragraph becomes a note, up to the Parameters: list,
    which is for developers.

    Parameters:
    - name: the command's name
    - function: the function that implements it, whose docstring is the help
    - aliases: other names of the command, listed in the help
    - options: dockscreen's options for the command, which the docstring does not list
    """
    summary, _, body = (function.__doc__ or "").strip().partition("\n")
    paragraphs = [p for p in body.split("\n\n") if p.strip()]
    notes = tuple(" ".join(p.split()) for p in paragraphs[:_end_of_help(paragraphs)])
    names = tuple(f"dockscreen compose {n}" for n in (name, *aliases)) if aliases else ()
    usage = f"dockscreen compose {name}" + (" [OPTIONS]" if options else "")
    return HelpTopic(usage, summary.strip().rstrip("."), notes, tuple(options), names, has_docker_help=False)


def _end_of_help(paragraphs: Sequence[str]) -> int:
    """Returns the index of the paragraph that starts the Parameters: list, or the number of paragraphs."""
    return next((i for i, p in enumerate(paragraphs) if p.strip().startswith("Parameters:")), len(paragraphs))


def topics(helps: Mapping[str, Callable[[str], HelpTopic]]) -> dict[str, HelpTopic]:
    """Returns the HelpTopic of each command, by name.

    Parameters:
    - helps: by command name, the help function of each command; given the name, it returns the HelpTopic
    """
    return {name: help_function(name) for name, help_function in helps.items()}


def topic_lines(help_topic: HelpTopic, follows_name: str, width: int | None) -> list[str]:
    """Returns the help for one command as lines wrapped to width.

    Parameters:
    - help_topic: the HelpTopic of the command
    - follows_name: the command whose own help follows ours; the end of the help announces that command's
      help, if the topic says that it follows
    - width: the width to wrap to; None for no wrapping
    """
    lines = [f"Usage:  {help_topic.usage}", "", *_paragraph(help_topic.summary, width)]
    if help_topic.aliases:
        lines += ["", "Aliases:", *_paragraph(", ".join(help_topic.aliases), width, "  ")]
    if help_topic.notes:
        lines += _notes(help_topic.notes, width)
    if help_topic.options:
        lines += ["", "Options:", *_table([(o._left_column(), o.text) for o in help_topic.options], width)]
    return lines + _follow_lines(help_topic.has_docker_help, follows_name)


def _overview(usage: str, summary: str, options: Iterable[HelpOption],
              sections: Iterable[tuple[str, Mapping[str, HelpTopic]]], closing_text: str, follows_name: str,
              width: int | None) -> list[str]:
    """Returns the help for dockscreen or compose as lines: options, then each (title, {name: HelpTopic})
    section, then closing_text and the announcement of follows_name's help.
    """
    lines = [f"Usage:  {usage}", "", *_paragraph(summary, width), "", "Options:",
             *_table([(o._left_column(), o.text) for o in options], width)]
    for title, topics in sections:
        lines += ["", title, *_table([(f"  {n}", t.summary) for n, t in sorted(topics.items())], width)]
    return lines + ["", *_paragraph(closing_text, width)] + _follow_lines(True, follows_name)


def _notes(texts: Iterable[str], width: int | None) -> list[str]:
    """Returns texts as lines: a paragraph after a blank line, or a list item (`- `) right after the previous
    text.
    """
    lines: list[str] = []
    for text in texts:
        if text.startswith("- "):
            lines += _item(text, width)
        else:
            lines += ["", *_paragraph(text, width)]
    return lines


def _table(rows: Sequence[tuple[str, str]], width: int | None) -> list[str]:
    """Returns (left, right) rows as lines. The right column starts after the widest left text, and wraps
    under itself. The right column does not wrap if width is None, or if wrapping would leave it under 20
    columns.
    """
    column = max(len(left_text) for left_text, _ in rows) + 3
    lines: list[str] = []
    for left_text, right_text in rows:
        if width is None or width - column < 20:
            lines.append(f"{left_text:<{column}}{right_text}")
            continue
        right_lines = textwrap.wrap(right_text, width - column, break_long_words=False,
                                    break_on_hyphens=False)
        lines.append(f"{left_text:<{column}}{right_lines[0]}")
        lines += [" " * column + continuation for continuation in right_lines[1:]]
    return lines


def _paragraph(text: str, width: int | None, indent: str = "") -> list[str]:
    """Returns text as lines wrapped to width, each indented; one line if width is None."""
    if width is None:
        return [indent + text]
    return textwrap.wrap(text, width, initial_indent=indent, subsequent_indent=indent,
                         break_long_words=False, break_on_hyphens=False)


def _item(text: str, width: int | None) -> list[str]:
    """Returns a list item (text starting with `- `) as lines: `  - text`, continued under the text."""
    if width is None:
        return [f"  {text}"]
    return textwrap.wrap(text[2:], width, initial_indent="  - ", subsequent_indent="    ",
                         break_long_words=False, break_on_hyphens=False)


def _follow_lines(has_docker_help: bool, name: str) -> list[str]:
    """Returns the lines that announce the own help of name after ours, if has_docker_help says that it
    follows.
    """
    return ["", f"{name} help follows:", ""] if has_docker_help and name else []


def docker_overview(commands: Mapping[str, HelpTopic], width: int | None) -> list[str]:
    """Returns the help for dockscreen itself, as lines wrapped to width.

    Parameters:
    - commands: {name: HelpTopic} of the commands dockscreen handles
    - width: the width to wrap to; None for no wrapping
    """
    return _overview(
        "dockscreen [OPTIONS] COMMAND",
        "Docker with security checks: dockscreen audits the commands that start containers and passes "
        "everything else to docker unchanged. Its own options go before the command, with docker's.",
        DOCKER_OPTIONS,
        [("Commands dockscreen handles:", commands)],
        "Run 'dockscreen COMMAND --help' for more information on a command.",
        "Docker's own", width)


def compose_overview(screened_topics: Mapping[str, HelpTopic], commands: Mapping[str, HelpTopic],
                     width: int | None
                     ) -> list[str]:
    """Returns the help for `dockscreen compose`, as lines wrapped to width.

    Parameters:
    - screened_topics: {name: HelpTopic} of the compose commands dockscreen audits
    - commands: {name: HelpTopic} of dockscreen's own compose commands
    - width: the width to wrap to; None for no wrapping
    """
    return _overview(
        "dockscreen compose [OPTIONS] COMMAND",
        "Docker Compose with security checks: dockscreen audits the project before the commands that "
        "start containers, and passes everything else to docker compose unchanged.",
        COMPOSE_OPTIONS,
        [("Commands dockscreen audits:", screened_topics), ("Commands dockscreen adds:", commands)],
        "Run 'dockscreen compose COMMAND --help' for more information on a command.",
        "Docker Compose's own", width)


def show(render_lines: Callable[[int | None], list[str]]) -> None:
    """Prints the lines that render_lines returns, wrapped to the width of the audit report. Without a
    terminal, this uses 80 columns, as docker does: people read help in less more often than they grep it.

    Parameters:
    - render_lines: returns the lines of the help, wrapped to the width it is given (None for no wrapping)
    """
    # flush: the exec of docker that follows discards unflushed buffers
    print("\n".join(render_lines(messages.report_width(fallback=HELP_FALLBACK_WIDTH))), flush=True)
