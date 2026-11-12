"""This package screens targets: it gathers what docker shows of them and what the command line says, and
has the policy judge it, in the stages each kind of target needs.

Contents:
- screener: the Screener, which gives the policy for a target and looks at images through docker
- projectscreening, with inspect, serviceinfo, imageusers and runoptions: a compose project, from loading
  its config to running compose on what was checked
- containerscreening: a container, created as `docker run` makes it or existing already
- bakescreening: the definition `docker buildx bake` would build
- userargs, runargs: reading command lines just far enough to find the users and the target
- userscreening: having the users a command line gives judged, and --as and --as-me resolved

Not here: the rules (policy); which command screens what, and what happens with the verdict (commands).

Constraints:
- No module here decides on its own whether something may run; every judgment comes from a Policy.
- Screening returns what was found, and leaves printing it to the command.
- docker is asked for facts, and to create what is to be looked at. Handing over to docker, to run what
  passed, is the command's.

Exceptions:
- projectscreening.check_and_run prints the notices and the verdict, and runs compose as a child: it is
  the shared body of compose up, create and run, and so a command's work.
- userscreening.resolve_user_args prints the notices of resolving names.

Dependencies: util, model, host and policy. Not commands.
"""
