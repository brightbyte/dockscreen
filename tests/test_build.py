from dockscreen.model.build import BakeDefinition, Build, fields


def test_compose_and_bake_name_the_sources_of_a_build_differently():
    compose = Build.from_compose({"context": ".", "dockerfile": "D", "additional_contexts": {"a": "x"}})
    bake = Build.from_bake({"context": ".", "dockerfile": "D", "contexts": {"a": "x"}})

    assert (compose.context, compose.dockerfile, compose.contexts) == (".", "D", {"a": "x"})
    assert (bake.context, bake.dockerfile, bake.contexts) == (".", "D", {"a": "x"})
    assert Build.from_compose("./app").context == "./app"  # `build: ./app` is a context alone


def test_a_bake_definition_has_a_build_per_target():
    bake = BakeDefinition({"group": {"default": {"targets": ["a"]}},
                           "target": {"a": {"context": "."}, "b": None}})

    found = {name: build.definition for name, build in bake.targets.items()}
    assert found == {"a": {"context": "."}, "b": {}}


def test_fields_reads_text_and_object_entries_alike():
    assert fields('type=local,"src=a,b"') == {"type": "local", "src": "a,b"}  # quoted as CSV
    assert fields({"type": "local", "src": "x"}) == {"type": "local", "src": "x"}
    assert fields("bare") == {} and fields(7) is None and fields({"type": 1}) is None
