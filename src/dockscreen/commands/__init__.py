"""This package holds one module for each command that dockscreen gates, named after the command. It also
holds the dispatchers that choose among the command modules (docker, docker_compose), and the help text
(helptext).

Contents:
- docker_*: the docker commands (run, create, start, exec, bake), and docker_compose for `docker compose`
- compose_*: the compose subcommands, one module per group that dockscreen screens alike
- docker, docker_compose: reading the command line and dispatching to a command
- projectrun: what compose up, create and run share, from screening the project to running compose
- helptext: the help of the commands

Not here: screening. A command has its targets screened (screen) and prints the findings. Then it either hands
over to docker or stops with an exit status.

Constraints:
- No module here judges a target or works out a change to it. A Policy found every refusal that a command
  reports, and the policy made every change that a command adds (hardening, the patches).
- A command calls docker only to hand over (exec, run as a child), and to start or remove a container that
  screening created.
- Nothing below commands may import from this package.

Exceptions:
- docker_run.gate removes a container whose user the policy decided, and creates it again with that user. This
  is a stage of screening, but containerscreening does not have it.

Dependencies: any package below it: util, model, host, policy and screen.
"""
