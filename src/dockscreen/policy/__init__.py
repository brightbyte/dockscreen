"""This package holds the policy: the rules that judge the facts screening gathers, and the decisions and
verdicts they give.

Contents:
- policy: the Policy, the one facade over the rules, with the settings they apply with
- rules: the rules themselves, grouped by what they judge (see its package)
- userdecision, imageuser, userdecisionview: deciding the user an image would run as, and describing it
- hardening, projectpatch, commandlinepatch, decisions: what screening changes in a project or a command line
  (the defaults, the user decided), held as patches to apply
- sections: which sections of the config files apply to an image and a project, and the settings
  that result
- projectfixes: the fixes `harden` writes out for a project, for the user to adopt
- finding, notice, report: what the rules find, and the verdict of a whole screening

Not here: getting the facts. A Policy judges what it is given; screen gets those facts through docker and
builds the Policy for each target (Screener). Not here either: what to do with a verdict (run, stop, which
exit status), which is the command's (commands).

Constraints:
- No module here calls docker. It imports nothing from host.docker but DockerError, because a failure to
  look is one of the facts. It imports nothing from host.runtime, which holds the docker (test_layering).
- The host is reached only through what is passed in: the settings, HostAccounts, SubordinateRanges.
- Nothing here prints.

Exceptions:
- report prints a verdict when the calling code asks a report to show itself (Report.show). Only the
  commands should print.
- Some code resolves paths with os.path.realpath, which reads the file system itself instead of facts that
  screen gathered: the rules on paths (rules.base.is_inside, and projectrules where it compares the
  directories of containers), and sections.effective_settings where it matches project sections.

Dependencies: util, model, and from host only hostusers and DockerError. Not screen or commands.
"""
