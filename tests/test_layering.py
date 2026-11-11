import ast
import pathlib

import pytest

SOURCE = pathlib.Path(__file__).parent.parent / "src" / "dockscreen"
# Each layer is a package and may import its own and the ones before it: the shared vocabulary (util),
# then the concepts that screening judges (model), then what describes the host (host), then the checks,
# which never call docker (screen), then reading the command line (cli), then screening targets with what
# docker shows of them (compose), then the commands, docker's and compose's dispatch among them. The module
# at the top is the entry point.
LAYERS = ("util", "model", "host", "screen", "cli", "compose", "commands", "entry")


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
    top = module.split(".")[1]
    return top if (SOURCE / top).is_dir() else "entry"


@pytest.mark.parametrize("path", MODULES, ids=lambda p: module_name(p))
def test_imports_go_from_the_entry_point_down_the_layers(path):
    module = module_name(path)
    for name in imported(path):
        assert LAYERS.index(layer(name)) <= LAYERS.index(layer(module)), f"{module} imports {name}"


@pytest.mark.parametrize("path", sorted((SOURCE / "screen").rglob("*.py")), ids=lambda p: module_name(p))
def test_the_checks_never_call_docker(path):
    # the policy decides from the facts it is given; a failure to get them (DockerError) is one of them
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            assert "dockscreen.host.docker" not in {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module == "dockscreen.host":
            assert "docker" not in {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module == "dockscreen.host.docker":
            assert {a.name for a in node.names} <= {"DockerError"}


@pytest.mark.parametrize("package", ["cli", "commands", "compose", "host", "model", "screen", "util"])
def test_packages_import_nothing_themselves(package):
    assert (SOURCE / package / "__init__.py").read_text() == ""
