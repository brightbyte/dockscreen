"""The daemon docker talks to, and whether it is this host's own.

The checks compare ids and paths with this host's: on another host's daemon they mean nothing.
"""

from dockscreen import commandline

REMOTE_MESSAGE = "the daemon is not the default local one; ids and paths cannot be checked"


def is_remote(global_args, env, docker):
    """Tells whether the daemon might not be this host's own, where host ids and paths mean nothing."""
    if commandline.option_values(global_args, "--host", "-H"):
        return True
    if commandline.option_values(global_args, "--context", "-c"):
        return True
    host = env.get("DOCKER_HOST", "")
    if host and not host.startswith("unix://"):
        return True
    if env.get("DOCKER_CONTEXT") not in (None, "", "default"):
        return True
    return docker.context() != "default"  # the current context can also come from docker's config file
