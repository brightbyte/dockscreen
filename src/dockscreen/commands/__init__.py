"""This package holds one module per command dockscreen gates, named after it, and the dispatchers that choose
among them (docker, docker_compose), with the help text (helptext).

Contents:
- docker_*: the docker commands (run, create, start, exec, bake), and docker_compose for `docker compose`
- compose_*: the compose subcommands, one module per group that is screened alike
- docker, docker_compose: reading the command line and dispatching to a command
- projectrun: what compose up, create and run share, from screening the project to running compose
- helptext: the help of the commands

Not here: screening. A command has its targets screened (screen), prints what was found, and hands over to
docker or stops with an exit status.

Constraints:
- No module here judges, or works out a change to a target: whatever it refuses, a Policy found, and
  whatever it adds, the policy made (hardening, the patches).
- docker is called only to hand over (exec, run as a child), and to start or remove a container that
  screening created.
- Nothing below commands may import from it.

Exceptions:
- compose_harden works out the fixes of `harden` itself, from the rules (servicerules, is_inside_any,
  image_problem): what can be fixed and how is the policy's.
- docker_run.gate removes a container whose user was decided and creates it again with that user, a
  stage of screening that containerscreening does not have.

Dependencies: any package below it: util, model, host, policy and screen.
"""
