"""The docker operations dockscreen needs, as thin wrappers around the real binary."""

import io
import json
import os
import signal
import subprocess
import tarfile

from dockscreen import messages

MAX_FILE_BYTES = 1 << 20  # /etc/passwd and /etc/group come from a hostile image
FORWARDED_SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


class DockerError(Exception):
    pass


class DockerNotFound(DockerError):
    """The docker binary does not exist."""


class Docker:
    def __init__(self, binary, run=subprocess.run, call=subprocess.call, popen=subprocess.Popen):
        """binary: the real docker (realdocker.locate)."""
        self.binary = binary
        self.run, self.call, self.popen = found(run), found(call), found(popen)

    def exec(self, args):
        """Replace this process with the real docker, keeping tty, signals and exit code."""
        try:
            os.execvp(self.binary, [self.binary, *args])
        except FileNotFoundError:
            messages.fatal(messages.DOCKER_NOT_FOUND)

    def create(self, args):
        """(exit code, container id or None). stderr stays on the terminal so pull progress shows."""
        result = self.run([self.binary, "create", *args], stdout=subprocess.PIPE, text=True)
        return result.returncode, (result.stdout.strip() if result.returncode == 0 else None)

    def inspect_container(self, ref):
        return self._inspect("container", ref)

    def inspect_image(self, ref):
        return self._inspect("image", ref)

    def _inspect(self, kind, ref):
        result = self.run([self.binary, kind, "inspect", "--", ref], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or f"docker {kind} inspect failed")
        return json.loads(result.stdout)[0]

    def read_file(self, container, path):
        """Contents of a file in a container that has not been started, or None if it is not there.

        Raises DockerError if the file is larger than MAX_FILE_BYTES.
        """
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
        args = ["start"]
        if attach:
            args.append("--attach")
        if interactive:
            args.append("--interactive")
        if detach_keys:
            args.append(f"--detach-keys={detach_keys}")
        return self.call([self.binary, *args, "--", container])

    def remove(self, container):
        self.run([self.binary, "rm", "--force", "--", container], capture_output=True)

    def project_directories(self, name):
        """The working directory label of each container, running or not, of the compose project `name`.

        Empty for one that has no such label. Raises DockerError if docker cannot say.
        """
        label = "com.docker.compose.project"
        result = self.run([self.binary, "ps", "--all", "--filter", f"label={label}={name}", "--format",
                           f'{{{{.Label "{label}.working_dir"}}}}'], capture_output=True, text=True)
        if result.returncode != 0:
            raise DockerError(result.stderr.strip() or "docker ps failed")
        return result.stdout.splitlines()

    def context(self):
        result = self.run([self.binary, "context", "show"], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None

    def capture(self, cmd):
        """Run cmd, a whole command line such as `docker compose ... config`, with its output as text."""
        return self.run(cmd, capture_output=True, text=True, check=False)

    def run_child(self, cmd):
        """Run cmd, a whole command line, with the terminal and exit code of the real thing.

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


def found(launch):
    """launch (subprocess.run, call or Popen), raising DockerNotFound if the binary does not exist."""
    def launch_found(cmd, **kwargs):
        try:
            return launch(cmd, **kwargs)
        except FileNotFoundError:
            raise DockerNotFound(messages.DOCKER_NOT_FOUND) from None
    return launch_found


def first_file_of_tar(data):
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            member = archive.next()
            if member is None or not member.isreg():
                return None
            return archive.extractfile(member).read().decode("utf-8", errors="replace")
    except tarfile.TarError:
        return None
