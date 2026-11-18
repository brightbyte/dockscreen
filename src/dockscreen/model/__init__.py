"""This package defines the targets the policy judges: compose projects and their services (project),
containers (container), images and the users they run as (image), builds (imagebuild), mounts (mounts),
where a value comes from (origin), and the settings of the config files (settings).

Contents:
- project, container, image, imagebuild: the targets, as docker describes them, together with their
  location and the origins of their values
- mounts: what a mount reaches on the host
- origin: who chose a value (the project, the image, the command line, the config file), which decides how
  far dockscreen trusts the value
- settings: dockscreen's settings as the config files give them, and the record of the image section that
  applies to an image

Not here: getting these facts, which is the job of the screen package (through docker) and of the host
package (the host and the config file); and judging them, which is the policy's job (policy).

Constraints: no module here calls docker, reads files or the host's accounts, or prints. Instances are
built from data given to them, so the policy can judge them in tests without docker.

Dependencies: none on other dockscreen packages; host, policy, screen and commands may depend on it.
"""
