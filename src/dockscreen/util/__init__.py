"""This package holds the vocabulary every other package shares: reading and writing ids (ids), the
command line and dockscreen's own options in it (commandline), and the messages dockscreen prints
(messages).

Contents:
- ids: uids, gids and `uid:gid`, as text and as numbers
- commandline: the docker and compose command lines, split into the options before the command, the
  command and its arguments, with dockscreen's own options taken out
- messages: the one place that writes to the terminal, and how a message looks there

Not here: what any of it means for screening. Whether an id is acceptable is the policy's (policy); what a
command line asks docker to do is read in screen (userargs, runargs).

Constraints:
- No module here calls docker or reads the host, beyond the terminal and the environment that messages
  needs for its output.
- Nothing here decides whether something may run. Texts may be defined here (commandline holds the ones
  about dockscreen's options), but only messages prints, and only when a caller tells it what.

Dependencies: none on other dockscreen packages; every other package may depend on this one.
"""
