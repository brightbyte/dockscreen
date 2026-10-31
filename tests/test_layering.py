import ast
import pathlib

import pytest

SOURCE = pathlib.Path(__file__).parent.parent / "src" / "dockscreen"
ENTRY = "dockscreen.docker_cli"
FRONT_ENDS = ("compose", "run", "bake")
SHARED = ("messages", "ids", "images", "commandline")
# Each layer may import its own and the ones before it: the shared vocabulary, then what describes the
# host (host), then the checks (screen), then the command line's own modules, then the front ends.
LAYERS = ("shared", "host", "screen", "command line", "front end", "entry point")


def module_name(path):
    parts = path.relative_to(SOURCE.parent).with_suffix("").parts
    return ".".join(parts[:-1] if parts[-1] == "__init__" else parts)


MODULES = sorted(SOURCE.rglob("*.py"))
KNOWN = {module_name(p) for p in MODULES}


def imported(path):
    """The dockscreen modules path imports, also inside functions; `from p import m` counts as p.m."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names |= {node.module, *(f"{node.module}.{a.name}" for a in node.names)}
    names = {n for n in names if n.split(".")[0] == "dockscreen" and n != "dockscreen"}
    return {n.rsplit(".", 1)[0] if n not in KNOWN else n for n in names}  # p.Name counts as p


def layer(module):
    """Returns the layer the module belongs to (LAYERS)."""
    top = module.split(".")[1:2]
    if module == ENTRY:
        return "entry point"
    if front_end(module):
        return "front end"
    if top in (["host"], ["screen"]):
        return top[0]
    return "shared" if not top or top[0] in SHARED else "command line"


def front_end(module):
    """Returns the front end the module belongs to, or None."""
    top = module.split(".")[1:2]
    return top[0] if top and top[0] in FRONT_ENDS else None


@pytest.mark.parametrize("path", MODULES, ids=lambda p: module_name(p))
def test_imports_go_from_the_entry_point_down_the_layers(path):
    module = module_name(path)
    for name in imported(path):
        assert LAYERS.index(layer(name)) <= LAYERS.index(layer(module)), f"{module} imports {name}"
        if layer(module) == "front end":  # and none imports another
            assert front_end(name) in (None, front_end(module)), f"{module} imports {name}"


@pytest.mark.parametrize("package", ["compose", "run", "host", "screen"])
def test_packages_import_nothing_themselves(package):
    assert (SOURCE / package / "__init__.py").read_text() == ""
