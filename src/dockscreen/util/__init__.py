"""This package holds the vocabulary every other package shares: reading and writing ids (ids), the
command line and dockscreen's own options in it (commandline), and the messages dockscreen prints
(messages).

Contents:
- ids: uids, gids and `uid:gid`, as text and as numbers
- commandline: the docker and compose command lines, split into the options before the command, the
  command and its arguments, with dockscreen's own options taken out
- messages: the one place that writes to the terminal, and how a message looks there

Not here: the meaning of any of it for screening. The policy decides whether an id is acceptable (policy),
and the screen package reads the requests that a command line makes of docker (userargs, runargs).

Constraints:
- No module here calls docker or reads the host, beyond the terminal and the environment that the module
  messages needs for its output.
- Nothing here decides whether something may run. Texts may be defined here (the module commandline holds
  the texts about dockscreen's options), but only the module messages prints, and only the text that a
  caller gives it.

Dependencies: none on other dockscreen packages; every other package may depend on this one.
"""
