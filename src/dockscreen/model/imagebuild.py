"""This module defines two classes. The class ImageBuild is a view of the build of one image as screening
sees it, from compose's `build:` section or from a target of `docker buildx bake`. The class
BakeDefinition is bake's definition of its builds.

Both kinds of build read a context, a Dockerfile and named contexts from this host, and may use a network
and the SSH agent; compose and bake give these different names (ImageBuild.keys). Bake also names the
places a build writes to (`output`, `cache-to`) and the other things it reads (`cache-from`, `secret`), as
`key=value,...` entries (fields).
"""

import csv
from typing import Any, NamedTuple, Self

# What compose's `build:` and a bake target call the context, the Dockerfile and the named contexts.
COMPOSE_KEYS = ("context", "dockerfile", "additional_contexts")
BAKE_KEYS = ("context", "dockerfile", "contexts")


class ImageBuild(NamedTuple):
    """View of the definition of one image build, from compose's `build:` or a target of `docker buildx bake`,
    for judging the files the build reads on this host. It holds the definition, the names it uses for the
    context, the Dockerfile and the named contexts, and the directory that its relative paths are relative
    to.

    Instances come from the classmethods from_compose and from_bake.

    Attributes:
    - definition: the build's keys, as compose or bake gives them; a dict that must not be changed in place
    - keys: the names the definition uses for the context, the Dockerfile and the named contexts
    - directory: the directory that its relative paths are relative to; everything the build reads must
      stay inside it
    """
    definition: dict[str, Any]
    keys: tuple[str, str, str]
    directory: str

    @classmethod
    def from_compose(cls, value: Any, directory: str) -> Self:
        """Returns the build that a compose service's `build:` value defines.

        Parameters:
        - value: the `build:` value: a context, or a section
        - directory: the project directory
        """
        return cls({"context": value} if isinstance(value, str) else value or {}, COMPOSE_KEYS, directory)

    @classmethod
    def from_bake(cls, target: dict[str, Any] | None, directory: str) -> Self:
        """Returns the build that a bake target defines.

        Parameters:
        - target: the target, as `bake --print` gives it; None for an empty target
        - directory: the directory bake ran in
        """
        return cls(target or {}, BAKE_KEYS, directory)

    @property
    def context(self) -> Any:
        """Returns its context: a path on this host, a URL, or None."""
        return self.definition.get(self.keys[0])

    @property
    def dockerfile(self) -> Any:
        """Returns its Dockerfile, relative to the context unless absolute; None for the default."""
        return self.definition.get(self.keys[1])

    @property
    def contexts(self) -> dict[str, Any]:
        """Returns its named contexts, by name."""
        return self.definition.get(self.keys[2]) or {}


class BakeDefinition(NamedTuple):
    """View of the definition that `docker buildx bake --print` gives, for judging its targets. It holds the
    definition and the directory bake ran in.

    Attributes:
    - definition: the targets and groups, as a JSON object; a dict that must not be changed in place
    - directory: the directory bake ran in; bake reads the targets' relative paths from there
    """
    definition: dict[str, Any]
    directory: str

    @property
    def targets(self) -> dict[str, ImageBuild]:
        """Returns its targets' builds, by target name."""
        targets = self.definition.get("target") or {}
        return {name: ImageBuild.from_bake(target, self.directory) for name, target in targets.items()}


def fields(entry: Any) -> dict[str, str] | None:
    """Returns the {key: value} of a `key=value,key=value` entry, or None if entry has another form.

    Newer buildx prints some entries (cache-from, cache-to, secret) as objects of the same keys.
    A bare word has no keys.
    """
    if isinstance(entry, dict):
        if not all(isinstance(value, str) for value in entry.values()):
            return None
        return {str(key): value for key, value in entry.items()}
    if not isinstance(entry, str):
        return None
    try:
        # buildx reads these as CSV, so a quoted value may hold commas
        parts = next(csv.reader([entry]), [])
    except csv.Error:
        return None
    pairs = [part.partition("=") for part in parts]
    return {key.strip(): value for key, equals, value in pairs if equals}
