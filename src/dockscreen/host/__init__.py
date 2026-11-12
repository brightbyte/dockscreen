"""This package describes the host and the caller dockscreen runs for, and holds the one way to reach
docker: the config file (config), the docker binary and daemon (docker), the host's accounts and
subordinate ranges (hostusers), the environment of the shell (shellenv), and all of it together for one
command (runtime).

Contents:
- config: the config files, read only when no one but their owner or root can have written them
- docker: running docker, and DockerError, which says why it failed with what docker printed
- hostusers: the accounts of this host and the subordinate id ranges
- shellenv: the variables a project takes from the shell
- runtime: the Runtime of one command, which holds the above

Not here: deciding anything about what was found. A failure is raised (DockerError), not turned into a
finding; that happens in policy (finding.failure_of). What a project or container is like is gathered in
screen, which calls docker through this package.

Constraints:
- No module here judges or refuses, and none prints a verdict. A failure is raised, with what docker said.
- Reading the host is the job here; changing it is not: docker is run for others (screen, commands),
  nothing here writes files of its own accord.

Exceptions:
- runtime warns about empty or relative PATH entries. Calling them unsafe is a judgment, which belongs
  to the policy.
- config.load_current creates the caller's config file when it is missing, which is a write done as a side
  effect of loading.

Dependencies: util and model only. Not policy, screen or commands.
"""
