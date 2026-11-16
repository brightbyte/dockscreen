"""This package describes the host and the user dockscreen runs for, and holds the one way to reach
docker: the config file (config), the docker binary and daemon (docker), the host's accounts and
subordinate ranges (hostusers), the environment of the shell (shellenv), and all of it together for one
command (runtime).

Contents:
- config: reading the config files (model.settings), only when no one but their owner or root can have
  written them
- docker: running docker, and DockerError, which says why it failed with what docker printed
- hostusers: the accounts of this host and the subordinate id ranges
- shellenv: the variables a project takes from the shell
- runtime: the Runtime of one command, which holds the above

Not here: deciding anything about the facts found. A failure here is an exception (DockerError); the
policy turns it into a finding (finding.failure_of). Which sections of the config files apply to a
target is the policy's too (policy.sections). screen gathers the facts about a project or container,
and calls docker through this package for them.

Constraints:
- No module here judges or refuses, and none prints a verdict. A failure is an exception that carries
  docker's output.
- Reading the host is the job here; changing it is not: docker runs here for others (screen, commands),
  and nothing here writes files of its own accord.

Exceptions:
- runtime warns about empty or relative PATH entries. Calling them unsafe is a judgment, which belongs
  to the policy.
- config.load_current creates the user's config file when it is missing, which is a write done as a side
  effect of loading.

Dependencies: util and model only. Not policy, screen or commands.
"""
