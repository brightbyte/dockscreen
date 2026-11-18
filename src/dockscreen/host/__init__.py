"""This package describes the host and the user that dockscreen runs for, and it holds the one way to
reach docker. Its parts are the config file (config), the docker binary and daemon (docker), the host's
accounts and subordinate ranges (hostusers), the environment of the shell (shellenv), and all of these
together for one command (runtime).

Contents:
- config: reading the config files (model.settings); it reads a file only when no one but its owner or
  root can have written it
- docker: running docker, and DockerError, which gives the reason docker failed and carries docker's output
- hostusers: the accounts of this host and the subordinate id ranges
- shellenv: the variables a project takes from the shell
- runtime: the Runtime of one command, which holds the above

Not here: deciding anything about the facts found. A failure here is an exception (DockerError); the
policy turns it into a finding (finding.failure_of). The policy also decides which sections of the config
files apply to a target (policy.sections). The screen package gathers the facts about a project or
container, and it calls docker through this package for them.

Constraints:
- No module here judges or refuses, and none prints a verdict. A failure is an exception that carries
  docker's output.
- The job here is reading the host, not changing it. Docker runs here on behalf of other packages
  (screen, commands), and nothing here writes files of its own accord.

Exceptions:
- The module runtime warns about empty or relative PATH entries. Calling them unsafe is a judgment,
  which belongs to the policy.
- The function config.load_current creates the user's config file when the file is missing. That is a
  write, done as a side effect of loading.

Dependencies: util and model only. Not policy, screen or commands.
"""
