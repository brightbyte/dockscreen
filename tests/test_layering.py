import ast
import pathlib

import pytest

SOURCE = pathlib.Path(__file__).parent.parent / "src" / "dockscreen"
ENTRY = "dockscreen.docker_cli"
FRONT_ENDS = ("compose", "run")


def module_name(path):
    parts = path.relative_to(SOURCE.parent).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


def imported(path):
    """The dockscreen modules path imports, also inside functions; `from p import m` counts as p.m."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names |= {node.module, *(f"{node.module}.{a.name}" for a in node.names)}
    return {n for n in names if n.split(".")[0] == "dockscreen" and n != "dockscreen"}


def layer(module):
    """compose or run for a front end's package and modules, else None for the core and the entry point."""
    parts = module.split(".")
    return parts[1] if len(parts) > 1 and parts[1] in FRONT_ENDS else None


MODULES = sorted(SOURCE.rglob("*.py"))


@pytest.mark.parametrize("path", MODULES, ids=lambda p: module_name(p))
def test_imports_go_from_the_entry_point_through_a_front_end_to_the_core(path):
    module = module_name(path)
    if module == ENTRY:
        return
    for name in imported(path):
        # the core imports neither front end, and neither front end the other
        assert layer(name) in (None, layer(module)), f"{module} imports {name}"
        assert name != ENTRY, f"{module} imports {name}"


@pytest.mark.parametrize("package", FRONT_ENDS)
def test_front_end_packages_import_nothing_themselves(package):
    assert (SOURCE / package / "__init__.py").read_text() == ""
