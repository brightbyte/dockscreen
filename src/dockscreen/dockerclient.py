"""The docker operations dockscreen needs, as thin wrappers around the real binary."""

import io
import json
import os
import signal
import subprocess
import tarfile
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NoReturn, Self

from dockscreen import messages

MAX_FILE_BYTES = 1 << 20  # /etc/passwd and /etc/group come from an untrusted image
FORWARDED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


class DockerError(Exception):
    pass


class DockerNotFound(DockerError):
    """The docker binary does not exist."""


class Docker:
    def __init__(self, binary: str, env: Mapping[str, str] | None = None) -> None:
        """Wraps binary, the real docker (runtime._real_docker).

        env: the environment of everything it runs; None for this process's own.
        """
        self.binary, self.env = binary, env
        self._run_proc = subprocess.run

    @classmethod
    def new_for_testing(cls, run_proc: Callable[..., Any], binary: str = "docker") -> Self:
        """Returns a Docker that runs binary with run_proc, a stand-in for subprocess.run."""
        docker = cls(binary)
        docker._run_proc = run_proc
        return docker

    def with_env(self, variables: Mapping[str, str]) -> Self:
        """Returns a Docker like this one that also passes variables in the environment of what it runs."""
        docker = type(self)(self.binary, {**(os.environ if self.env is None else self.env), **variables})
        docker._run_proc = self._run_proc
        return docker

    def run(self, args: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
        """Runs `docker args` to completion, with kwargs as subprocess.run takes them, and returns the
        completed process. Raises DockerNotFound if the binary does not exist.
        """
        return self._launch(self._run_proc, [self.binary, *args], **kwargs)

    def exec(self, args: Sequence[str]) -> NoReturn:
        """Replaces this process with `docker args`, keeping tty, signals and exit code.

        Exits with a message if the binary does not exist.
        """
        try:
            if self.env is None:
                os.execvp(self.binary, [self.binary, *args])
            else:
                os.execvpe(self.binary, [self.binary, *args], self.env)
        except FileNotFoundError:
            messages.fatal(messages.DOCKER_NOT_FOUND)

    def create(self, args: Sequence[str]) -> tuple[int, str | None]:
        """Runs `docker create args` and returns (exit code, container id or None if it failed).

        stderr stays on the terminal, so pull progress shows.
        """
        result = self.run(["create", *args], stdout=subprocess.PIPE, text=True)
        return result.returncode, (result.stdout.strip() if result.returncode == 0 else None)

    def inspect_container(self, ref: str) -> dict[str, Any]:
        """Returns `docker container inspect` of ref, as a dict.

        Raises DockerError if there is no such container.
        """
        return self._inspect("container", ref)

    def inspect_image(self, ref: str) -> dict[str, Any]:
        """Returns `docker image inspect` of ref, as a dict. Raises DockerError if there is no such image."""
        return self._inspect("image", ref)

    def _inspect(self, kind: str, ref: str) -> dict[str, Any]:
        # `--`: a ref from the project or the command line must not be read as an option
        result = self.run([kind, "inspect", "--", ref], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or f"docker {kind} inspect failed")
        return json.loads(result.stdout)[0]

    def read_file(self, container: str, path: str) -> str | None:
        """Returns the text of a file in a container that has not been started, or None if it cannot be read.

        Raises DockerError if the file is larger than MAX_FILE_BYTES.
        """
        # `docker cp SRC -` streams a tar archive to stdout, so nothing from the image is written
        # to the host; -L reads through a symlink, as docker does when it resolves the user
        process = self._launch(subprocess.Popen, [self.binary, "cp", "-L", f"{container}:{path}", "-"],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        data = process.stdout.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            process.kill()
            process.wait()
            raise DockerError(f"{path} in the image is larger than {MAX_FILE_BYTES} bytes")
        if process.wait() != 0:
            return None

        # `docker cp` returns a tar archive of one file
        return _first_file_of_tar(data)

    def start(self, container: str, attach: bool, interactive: bool, detach_keys: str | None) -> int:
        """Runs `docker start` on container with the given attach options and returns its exit status."""
        args = ["start"]
        if attach:
            args.append("--attach")
        if interactive:
            args.append("--interactive")
        if detach_keys:
            args.append(f"--detach-keys={detach_keys}")
        return self.run([*args, "--", container]).returncode

    def remove(self, container: str) -> None:
        """Removes container, running or not, ignoring failures."""
        self.run(["rm", "--force", "--", container], capture_output=True)

    def label_values(self, label: str, value: str, wanted: str) -> list[str]:
        """Returns the value of the label wanted of each container, running or not, whose label is value.

        Empty for a container without wanted. Raises DockerError if docker cannot say.
        """
        result = self.run(["ps", "--all", "--filter", f"label={label}={value}", "--format",
                           f'{{{{.Label "{wanted}"}}}}'], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or "docker ps failed")
        return result.stdout.splitlines()

    def context(self) -> str | None:
        """Returns the name of the current docker context, or None if docker cannot tell."""
        result = self.run(["context", "show"], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None

    def capture(self, cmd: Sequence[str]) -> subprocess.CompletedProcess:
        """Runs cmd, a whole command line such as `docker compose ... config`, and returns the completed
        process with its output captured as text.
        """
        return self._launch(self._run_proc, cmd, capture_output=True, text=True, check=False)

    def run_child(self, cmd: Sequence[str]) -> int:
        """Runs cmd, a whole command line, on this terminal and returns its exit status, 128 + the signal
        if a signal ended it, or 127 if docker does not exist.

        Termination signals are passed on; Ctrl-C reaches the child from the terminal itself.
        """
        try:
            process = self._launch(subprocess.Popen, cmd)
        except DockerNotFound:
            messages.notice(messages.DOCKER_NOT_FOUND)
            return 127

        def forward(number: int, frame: Any) -> None:
            process.send_signal(number)

        previous = {s: signal.signal(s, forward) for s in FORWARDED_SIGNALS}
        try:
            while True:
                try:
                    code = process.wait()
                    break
                except KeyboardInterrupt:
                    continue  # the terminal sent the same SIGINT to the child
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
        return 128 - code if code < 0 else code

    def _launch(self, launch: Callable[..., Any], cmd: Sequence[str], **kwargs: Any) -> Any:
        """Returns what launch (_run_proc or subprocess.Popen) returns for cmd, run with env if that is
        set. Raises DockerNotFound if the binary does not exist.
        """
        if self.env is not None:
            kwargs["env"] = self.env
        try:
            return launch(cmd, **kwargs)
        except FileNotFoundError:
            raise DockerNotFound(messages.DOCKER_NOT_FOUND) from None


def _first_file_of_tar(data: bytes) -> str | None:
    """Returns the text of the first entry of a tar archive, or None if that is not a regular file or
    the archive cannot be read.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.next()
            file = archive.extractfile(member) if member is not None and member.isreg() else None
            return None if file is None else file.read().decode("utf-8", errors="replace")
    except tarfile.TarError:
        return None
