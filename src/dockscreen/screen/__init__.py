"""This package screens targets: it gathers what docker shows of them and what the command line says, and
has the policy judge it, in the stages each kind of target needs.

Contents:
- screener: the Screener, which gives the policy for a target and looks at images through docker
- projectscreening, with inspect, serviceinfo, imageusers and runoptions: a compose project, from loading
  its config to the generated file compose is to run from
- containerscreening: a container, created as `docker run` makes it or existing already
- bakescreening: the definition `docker buildx bake` would build
- userargs, runargs: reading command lines just far enough to find the users and the target
- userscreening: having the users a command line gives judged, and --as and --as-me resolved

Each screening module gives, in its docstring, the reasons its kind of target needs screening, and the
reasons for the way it is done.

Not here: the rules (policy); which command screens what, and what happens with the verdict (commands).

Constraints:
- No module here decides on its own whether something may run; every judgment comes from a Policy.
- Screening returns what was found, and leaves printing it to the command.
- Modules here ask docker for facts, and have it create the containers they look at. Handing over to
  docker, to run the targets that passed, is the command's.

Dependencies: util, model, host and policy. Not commands.
"""
