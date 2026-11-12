"""This package holds the policy: the rules that judge the facts screening gathers, and the decisions and
verdicts they give.

Contents:
- policy: the Policy, the one facade over the rules, with the settings they apply with
- rules: the rules themselves, grouped by what they judge (see its package)
- userdecision, imageuser, userdecisionview: deciding the user an image would run as, and describing it
- hardening, projectpatch, commandlinepatch, decisions: what screening changes in a project or a command line
  (the defaults, the user decided), held as patches to apply
- projectfixes: the fixes `harden` writes out for a project, for the person to adopt
- finding, notice, report: what the rules find, and the verdict of a whole screening

Not here: getting the facts. A Policy judges what it is given; screen gets it through docker and builds
the Policy for each target (Screener). Not here either: what to do with a verdict (run, stop, which exit
status), which is the command's (commands).

Constraints:
- No module here calls docker: it imports nothing from host.docker but DockerError, a failure to look
  being one of the facts, and nothing from host.runtime, which holds the docker (test_layering).
- The host is reached only through what is passed in: the config, HostAccounts, SubordinateRanges.
- Nothing here prints.

Exceptions:
- report prints a verdict when a caller asks it to show itself (Report.show), where only the commands
  should print.
- The rules on paths (rules.base.is_inside, and projectrules where it compares the directories of
  containers) resolve paths with os.path.realpath, which reads the file system itself rather than facts
  gathered by screen.

Dependencies: util, model, and from host only config, hostusers and DockerError. Not screen or commands.
"""
