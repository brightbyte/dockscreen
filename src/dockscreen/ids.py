"""Numeric uids and gids, and the uid and gid compose files see.

dockscreen passes UID and GID, the real ids of the caller, in the environment of the compose commands
it runs, for compose files to interpolate (`user: "${UID}:${GID}"`); values already in the environment
are overridden. Running as these ids is not allowed unless --allow-me is given (see idrules): passing
them only makes the project's intent readable.

Ids given by the command line, the config file or the project are ASCII digits only. How docker reads
ids out of an image's passwd and group files is different, and lives in imageuser.
"""

EXPORTED = ("UID", "GID")


def exported(me):
    """Returns the variables UID and GID for me, the caller's real (uid, gid)."""
    return dict(zip(EXPORTED, (str(i) for i in me)))


def is_id(text):
    """Tells whether text is a numeric id, which is ASCII digits only."""
    return text.isascii() and text.isdigit()  # isdigit alone takes other scripts' digits, which int() reads


def parse_id(value):
    """Returns value as a numeric id, or None if its text is not one (is_id)."""
    text = str(value)
    return int(text) if is_id(text) else None


def parse_user(spec):
    """Returns (uid, gid) for a spec "uid:gid" of two numeric ids, or None for anything else."""
    user, colon, group = spec.partition(":")
    if not (colon and is_id(user) and is_id(group)):
        return None
    return int(user), int(group)


def format_user(ids):
    """Formats ids, a (uid, gid) pair, as "uid:gid"."""
    uid, gid = ids
    return f"{uid}:{gid}"
