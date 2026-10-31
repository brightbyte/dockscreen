"""The docker operations dockscreen needs, as thin wrappers around the real binary."""

import io
import json
import os
import signal
import subprocess
import tarfile

from dockscreen import messages

MAX_FILE_BYTES = 1 << 20  # /etc/passwd and /etc/group come from an untrusted image
FORWARDED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


class DockerError(Exception):
    pass


class DockerNotFound(DockerError):
    """The docker binary does not exist."""


class Docker:
    def __init__(self, binary, run=subprocess.run, call=subprocess.call, popen=subprocess.Popen, env=None):
        """Wraps binary, the real docker (runtime.real_docker); run, call and popen launch it.

        env: the environment of everything it runs; None for this process's own.
        """
        self.binary, self.env = binary, env
        self._launchers = (run, call, popen)
        self.run, self.call, self.popen = (_found(launch, env) for launch in self._launchers)

    def exporting(self, variables):
        """Returns a Docker like this one that also passes variables in the environment of what it runs."""
        env = {**(os.environ if self.env is None else self.env), **variables}
        return Docker(self.binary, *self._launchers, env=env)

    def exec(self, args):
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

    def create(self, args):
        """Runs `docker create args` and returns (exit code, container id or None if it failed).

        stderr stays on the terminal, so pull progress shows.
        """
        result = self.run([self.binary, "create", *args], stdout=subprocess.PIPE, text=True)
        return result.returncode, (result.stdout.strip() if result.returncode == 0 else None)

    def inspect_container(self, ref):
        """Returns `docker container inspect` of ref, as a dict.

        Raises DockerError if there is no such container.
        """
        return self._inspect("container", ref)

    def inspect_image(self, ref):
        """Returns `docker image inspect` of ref, as a dict. Raises DockerError if there is no such image."""
        return self._inspect("image", ref)

    def _inspect(self, kind, ref):
        # `--`: a ref from the project or the command line must not be read as an option
        result = self.run([self.binary, kind, "inspect", "--", ref], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or f"docker {kind} inspect failed")
        return json.loads(result.stdout)[0]

    def read_file(self, container, path):
        """Returns the text of a file in a container that has not been started, or None if it cannot be read.

        Raises DockerError if the file is larger than MAX_FILE_BYTES.
        """
        # `docker cp SRC -` streams a tar archive to stdout, so nothing from the image is written
        # to the host; -L reads through a symlink, as docker does when it resolves the user
        process = self.popen([self.binary, "cp", "-L", f"{container}:{path}", "-"],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        data = process.stdout.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            process.kill()
            process.wait()
            raise DockerError(f"{path} in the image is larger than {MAX_FILE_BYTES} bytes")
        if process.wait() != 0:
            return None
        return first_file_of_tar(data)

    def start(self, container, attach, interactive, detach_keys):
        """Runs `docker start` on container with the given attach options and returns its exit status."""
        args = ["start"]
        if attach:
            args.append("--attach")
        if interactive:
            args.append("--interactive")
        if detach_keys:
            args.append(f"--detach-keys={detach_keys}")
        return self.call([self.binary, *args, "--", container])

    def remove(self, container):
        """Removes container, running or not, ignoring failures."""
        self.run([self.binary, "rm", "--force", "--", container], capture_output=True)

    def project_directories(self, name):
        """Returns the working directory label of each container, running or not, of compose project `name`.

        Empty for one that has no such label. Raises DockerError if docker cannot say.
        """
        label = "com.docker.compose.project"
        result = self.run([self.binary, "ps", "--all", "--filter", f"label={label}={name}", "--format",
                           f'{{{{.Label "{label}.working_dir"}}}}'], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or "docker ps failed")
        return result.stdout.splitlines()

    def context(self):
        """Returns the name of the current docker context, or None if docker cannot tell."""
        result = self.run([self.binary, "context", "show"], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None

    def capture(self, cmd):
        """Runs cmd, a whole command line such as `docker compose ... config`, and returns the completed
        process with its output captured as text.
        """
        return self.run(cmd, capture_output=True, text=True, check=False)

    def run_child(self, cmd):
        """Runs cmd, a whole command line, on this terminal and returns its exit status, 128 + the signal
        if a signal ended it, or 127 if docker does not exist.

        Termination signals are passed on; Ctrl-C reaches the child from the terminal itself.
        """
        try:
            process = self.popen(cmd)
        except DockerNotFound:
            messages.notice(messages.DOCKER_NOT_FOUND)
            return 127

        def forward(number, frame):
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


def _found(launch, env):
    """Wraps launch (subprocess.run, call or Popen) to run with env, unless that is None, and to raise
    DockerNotFound if the binary does not exist.
    """
    def launch_found(cmd, **kwargs):
        if env is not None:
            kwargs["env"] = env
        try:
            return launch(cmd, **kwargs)
        except FileNotFoundError:
            raise DockerNotFound(messages.DOCKER_NOT_FOUND) from None
    return launch_found


def first_file_of_tar(data):
    """Returns the text of the first entry of a tar archive, or None if that is not a regular file or
    the archive cannot be read.
    """
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.next()  # `docker cp` of one file archives just that file
            if member is None or not member.isreg():
                return None
            return archive.extractfile(member).read().decode("utf-8", errors="replace")
    except tarfile.TarError:
        return None
