"""This package defines the targets the policy judges: compose projects and their services (project),
containers (container), images and the users they run as (image), builds (imagebuild), mounts (mounts),
where a value comes from (origin), and the settings of the config files (settings).

Contents:
- project, container, image, imagebuild: the targets, as docker describes them, with what is known of
  where they are and where their values come from
- mounts: what a mount reaches on the host
- origin: who chose a value (the project, the image, the command line, the config file), which decides how
  far it is trusted
- settings: dockscreen's settings as the config files give them, and which image section applies to an
  image

Not here: getting these facts, which is screen's (through docker) and host's (the host and the config
file); judging them, which is the policy's (policy).

Constraints: no module here calls docker, reads files or the host's accounts, or prints. Instances are
built from data given to them, so the policy can judge them in tests without docker.

Dependencies: none on other dockscreen packages; host, policy, screen and commands may depend on it.
"""
