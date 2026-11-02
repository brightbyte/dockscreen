"""This module defines the scope a command is screened in: the caller and this host (the runtime), whether
the caller's own ids are allowed, and the directory the project is in.

Everything the checks of one image, service or container need follows from it: the settings of the
config file with the image and project sections that apply (config.effective), the id rules with those
settings, and the policy context (policy.Policy) built from them.
"""

from collections.abc import Mapping
from typing import Any, NamedTuple, Self

from dockscreen.host import config, hostusers
from dockscreen.host.dockerclient import Docker
from dockscreen.host.runtime import Runtime
from dockscreen.model.origin import TRUSTED, Origin
from dockscreen.screen import idrules, policy


class Scope(NamedTuple):
    """Scope a command is screened in: the runtime, whether --allow-me (or --as-me) allows the caller's own
    ids, and the compose project's directory, if there is a project.
    """
    runtime: Runtime
    allow_me: bool = False
    project_dir: str | None = None  # for docker run, the current directory stands in

    @property
    def docker(self) -> Docker:
        """Returns the docker to pull, build, create, inspect and start with."""
        return self.runtime.docker

    @property
    def ids(self) -> idrules.Rules:
        """Returns the id rules with the config file's top-level settings."""
        return idrules.Rules.for_runtime(self.runtime, self.allow_me)

    @property
    def local(self) -> hostusers.HostAccounts:
        """Returns the accounts of this host, for naming the users an image runs as."""
        return self.runtime.accounts

    @property
    def directory(self) -> str:
        """Returns the directory a bind mount is judged against: the project's, else the current one."""
        return self.project_dir or self.runtime.cwd

    @property
    def settings(self) -> config.Config:
        """Returns the config file's settings for this directory's project, without any image section."""
        return config.effective(self.runtime.settings, None, self.directory)

    def for_image(self, repository: str | None) -> tuple[config.Config, idrules.Rules]:
        """Returns (settings, id rules) with the image section for repository applied (None: none applies)."""
        settings = config.effective(self.runtime.settings, repository, self.directory)
        return settings, self.ids.with_settings(settings)

    def policy_context(self, repository: str | None, trust: frozenset[Origin] = TRUSTED) -> policy.Policy:
        """Returns the policy context for a container of an image from repository (None: no image section
        applies), with this scope's directory as the project's, trusting the origins in trust.
        """
        settings, _ = self.for_image(repository)
        found = policy.Policy.for_settings(settings, self.directory, self.ids, self.runtime.config_file)
        return found.with_trust(trust)

    def project_policy(self, verified: Mapping[str, str] | None = None) -> policy.Policy:
        """Returns the policy context for the project, which gives each service the settings of its image
        section, if one applies (policy.Policy.for_service).

        Before the images are there, that is the section the image name points to; verified, once they are,
        maps each service to the section its image was proven to have been pulled for (config.section_for).
        """
        def scope(name: str, service: dict[str, Any]) -> policy.Policy:
            if verified is None:
                image = str(service.get("image") or "")
                repository = config.name_matches(self.runtime.settings, image, "build" in service)
            else:
                repository = verified.get(name)
            return self.policy_context(repository)

        return self.policy_context(None).with_scope(scope)

    def with_allow_me(self, allow_me: bool) -> Self:
        """Returns this scope with the caller's own ids allowed too if allow_me (--allow-me, --as-me)."""
        return self._replace(allow_me=True) if allow_me else self

    def with_project_dir(self, project_dir: str) -> Self:
        """Returns this scope for the compose project in project_dir."""
        return self._replace(project_dir=project_dir)
