#!/usr/bin/env python3
"""This module measures how much a reader of dockscreen's source has to take in, so that a refactoring can be
compared with what it started from: files, classes, effective lines, and the cyclomatic complexity of its
functions.

Effective lines carry code: blank lines, comments and docstrings do not count. Cyclomatic complexity is
McCabe's, counted from the syntax tree: one, plus one for each `if`/`elif`, loop, `except`, conditional
expression, `match` case, comprehension clause, and operand of `and`/`or` past the first. A nested function
counts on its own. Functions of complexity 1 have no branch at all; many of them mean many hops, which the
complexity alone does not show.

Usage: tools/metrics.py [--top N] [WHAT ...], where each WHAT is a git revision (main, HEAD~3) or a
directory that holds src/dockscreen; HEAD's working tree if none is given.
"""

import argparse
import ast
import io
import pathlib
import statistics
import subprocess
import sys
import tarfile
import tempfile
import tokenize
from typing import NamedTuple

SOURCE = pathlib.Path("src", "dockscreen")
SKIPPED_TOKENS = (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT,
                  tokenize.ENDMARKER)
BRANCHES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.IfExp, ast.ExceptHandler, ast.match_case)
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)


class Measures(NamedTuple):
    """Measures of one tree of source files: files, classes, effective lines, and the complexity of each
    function by its place (module path:line:name).
    """
    files: int
    classes: int
    lines: int
    complexity: dict[str, int]


def effective_lines(source: str, tree: ast.Module) -> int:
    """Returns the number of lines of source that carry code, leaving out docstrings (tree is its syntax)."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, *FUNCTIONS)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                docstrings.update(range(first.lineno, (first.end_lineno or first.lineno) + 1))
    code: set[int] = set()
    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type not in SKIPPED_TOKENS:
            code.update(range(token.start[0], token.end[0] + 1))
    return len(code - docstrings)


def complexity(function: ast.AST) -> int:
    """Returns the cyclomatic complexity of function, without the functions and lambdas nested in it."""
    found, pending = 1, list(ast.iter_child_nodes(function))
    while pending:
        node = pending.pop()
        if isinstance(node, (*FUNCTIONS, ast.Lambda)):
            continue
        if isinstance(node, BRANCHES):
            found += 1
        elif isinstance(node, ast.BoolOp):
            found += len(node.values) - 1
        elif isinstance(node, ast.comprehension):
            found += 1 + len(node.ifs)
        pending.extend(ast.iter_child_nodes(node))
    return found


def measure(root: pathlib.Path) -> Measures:
    """Returns the Measures of the Python files under root."""
    files, classes, lines = 0, 0, 0
    functions: dict[str, int] = {}
    for path in sorted(root.rglob("*.py")):
        source = path.read_text()
        tree = ast.parse(source)
        files += 1
        classes += sum(isinstance(node, ast.ClassDef) for node in ast.walk(tree))
        lines += effective_lines(source, tree)
        for node in ast.walk(tree):
            if isinstance(node, FUNCTIONS):
                functions[f"{path.relative_to(root)}:{node.lineno}:{node.name}"] = complexity(node)
    return Measures(files, classes, lines, functions)


def _source_of(what: str, scratch: pathlib.Path) -> pathlib.Path:
    """Returns the source directory of what: a directory that holds it, or a git revision, whose source is
    extracted into scratch.
    """
    if pathlib.Path(what, SOURCE).is_dir():
        return pathlib.Path(what, SOURCE)
    archive = subprocess.run(["git", "archive", what, str(SOURCE)], capture_output=True, check=True).stdout
    target = scratch / what.replace("/", "_")
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(target, filter="data")
    return target / SOURCE


def _report(what: str, found: Measures, top: int) -> None:
    """Prints the measures of what, with its top most complex functions."""
    values = list(found.complexity.values())
    print(f"{what}: files={found.files} classes={found.classes} eloc={found.lines} functions={len(values)} "
          f"complexity={sum(values)} mean={statistics.mean(values):.2f} median={statistics.median(values)} "
          f">=10:{sum(v >= 10 for v in values)} >=6:{sum(v >= 6 for v in values)} "
          f"ones={sum(v == 1 for v in values)}")
    for place, value in sorted(found.complexity.items(), key=lambda item: -item[1])[:top]:
        print(f"  {value:3} {place}")


def main(argv: list[str]) -> int:
    """Measures each revision or directory argv names (the working tree if none), and prints the results."""
    parser = argparse.ArgumentParser(description="Measure dockscreen's source.")
    parser.add_argument("--top", type=int, default=10, help="most complex functions to list for each")
    parser.add_argument("what", nargs="*", default=["."], help="git revisions or directories")
    args = parser.parse_args(argv)
    with tempfile.TemporaryDirectory() as scratch:
        for what in args.what:
            _report(what, measure(_source_of(what, pathlib.Path(scratch))), args.top)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
