"""Image references, read and normalised as docker reads them."""

import re

DEFAULT_DOMAIN = "docker.io"
LEGACY_DOMAINS = frozenset({"index.docker.io", "registry-1.docker.io"})
# distribution/reference: a path component is lower-case alphanumerics and separators.
COMPONENT = re.compile(r"^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$")


def split_reference(reference: str) -> tuple[str, str, str]:
    """Splits an image reference into (normalised repository, tag, digest) as docker reads it:
    `mariadb` is docker.io/library/mariadb. Tag and digest are empty if not given.

    Raises ValueError for something that is not a reference.
    """
    name, _, digest = reference.partition("@")
    tag = ""
    last_slash = name.rfind("/")
    if ":" in name[last_slash + 1:]:  # a colon before the last slash is a registry's port, not a tag
        name, _, tag = name.rpartition(":")
    first, slash, rest = name.partition("/")
    # docker's rule: the first component is a registry only if it looks like a host
    if slash and ("." in first or ":" in first or first == "localhost"):
        domain, path = first, rest
    else:
        domain, path = DEFAULT_DOMAIN, name
    if domain in LEGACY_DOMAINS:
        domain = DEFAULT_DOMAIN
    if domain == DEFAULT_DOMAIN and "/" not in path:
        path = "library/" + path
    if not path or not all(COMPONENT.match(part) for part in path.split("/")):
        raise ValueError(f"{reference!r} is not an image reference")
    return f"{domain}/{path}", tag, digest


def repository(reference: str) -> str | None:
    """Returns the normalised repository of a reference, or None if it is not one."""
    try:
        return split_reference(reference)[0]
    except ValueError:
        return None


def _shown(repository: str) -> str:
    """Returns a normalised repository as people write it: `mariadb` for docker.io/library/mariadb."""
    for prefix in (f"{DEFAULT_DOMAIN}/library/", f"{DEFAULT_DOMAIN}/"):
        if repository.startswith(prefix):
            return repository[len(prefix):]
    return repository


def section_hint(reference: str, config_file: str, built: bool = False) -> str | None:
    """Returns how config_file could give this image a user, or None for a built image or a reference
    that is not one.
    """
    name = repository(reference)
    if built or not name:
        return None
    return f"set user under [images.\"{_shown(name)}\"] in {config_file}"
