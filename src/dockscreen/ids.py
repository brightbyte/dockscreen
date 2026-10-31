"""Numeric uids and gids, as the command line, the config file and projects give them.

Ids given by the command line, the config file or the project are ASCII digits only. How docker reads
ids out of an image's passwd and group files is different, and lives in imageuser.
"""

def is_id(text: str) -> bool:
    """Tells whether text is a numeric id, which is ASCII digits only."""
    return text.isascii() and text.isdigit()  # isdigit alone takes other scripts' digits, which int() reads


def parse_id(value: object) -> int | None:
    """Returns value as a numeric id, or None if its text is not one (is_id)."""
    text = str(value)
    return int(text) if is_id(text) else None


def parse_user(spec: str) -> tuple[int, int] | None:
    """Returns (uid, gid) for a spec "uid:gid" of two numeric ids, or None for anything else."""
    user, colon, group = spec.partition(":")
    if not (colon and is_id(user) and is_id(group)):
        return None
    return int(user), int(group)


def format_user(ids: tuple[int, int]) -> str:
    """Formats ids, a (uid, gid) pair, as "uid:gid"."""
    uid, gid = ids
    return f"{uid}:{gid}"
