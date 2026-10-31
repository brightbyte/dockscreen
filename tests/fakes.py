"""Fakes for the docker side of dockscreen: images with users, and the compose commands around them."""
import json
import os
import subprocess

from dockscreen import config, hostusers, idrules, imagedecision
from dockscreen.dockerclient import DockerError

PASSWD = ("app:x:100000:100001::/:/bin/sh\nroot:x:0:0::/:/bin/sh\nweb:x:1000:1000::/:/bin/sh\n"
          "pg:x:998:998::/:/bin/sh\nnobody:x:65534:65534::/:/bin/sh\n")
GROUP = "app:x:100001:\npg:x:998:\n"


SUBCOMMANDS = ("pull", "build", "up", "run", "create", "watch", "scale")


class NoSubordinate:
    def contains(self, kind, value):
        return False


# The caller: alice in Accounts, so that 1000 is someone else (daniel, a local account), whatever this
# process runs as.
ME = (4242, 4343)


def rules(me=ME, allow_me=False, local=None, settings=None, subordinate=None):
    """idrules.Rules for the host of Accounts, with the default config unless settings says otherwise.

    The caller is ME.
    """
    settings = settings or config.Config()
    return idrules.Rules(me, allow_me, settings.nobody_range, settings.default_user, local or Accounts(),
                         subordinate or NoSubordinate())


class Accounts:
    """hostusers.HostAccounts for a host with root, an account `daniel` with uid and gid 1000, the group
    `docker` (999), and nobody.

    By name there is also alice (4242:4343), who has no matching group. Her ids are not listed as local
    accounts: tests use them as the caller's own, which idrules must tell apart from someone else's.
    """

    def user(self, name):
        users = {"root": (0, 0), "nobody": (65534, 65534), "daniel": (1000, 1000), "alice": (4242, 4343)}
        return users.get(name)

    def group(self, name):
        return {"root": 0, "nogroup": 65534, "nobody": 65534, "daniel": 1000, "docker": 999}.get(name)

    def user_name(self, uid):
        return {0: "root", 1000: "daniel"}.get(uid)

    def group_name(self, gid):
        return {0: "root", 1000: "daniel", 999: "docker"}.get(gid)


REAL_RESOLVE = hostusers._resolve_account  # tests that replace it by host_account must not recurse


def host_account(name, accounts=None):
    """hostusers._resolve_account against the host of Accounts, whatever accounts are given."""
    return REAL_RESOLVE(name, Accounts())


def make_runtime(**fields):
    """A Runtime with the default config, the accounts of Accounts, no subordinate ids and ME as the
    caller, whatever this host has, and a FakeImages with no images as its docker; fields replace any of
    that. The environment, home and directory are this process's own.
    """
    from dockscreen.runtime import Runtime
    if "docker" not in fields:
        fields["docker"] = FakeImages()
        fake_compose(fields["docker"])
    defaults = {"settings": config.Config(), "accounts": Accounts(), "subordinate": NoSubordinate(),
                "me": ME, "env": os.environ, "home": os.path.expanduser("~"), "cwd": os.getcwd()}
    return Runtime(**{**defaults, **fields})


class Executing:
    """What a fake docker records of exec: every argv it was replaced with, and the compose ones."""

    binary = "docker"

    def exec(self, args):
        self.executed.append(list(args))
        if args[:1] == ["compose"]:
            self.forwarded.append(list(args[1:]))

    def with_env(self, variables):
        return self


class FakeImages(Executing):
    """A docker that knows images by name: the user each sets, and which are present locally."""

    def __init__(self, users=None, local=None, digests=None):
        self.executed, self.forwarded = [], []
        self.users = users or {}
        self.digests = digests or {}  # image name -> RepoDigests: where it was pulled from
        self.local = set(self.users if local is None else local)
        self.calls = []
        self.created = []
        self._containers = {}
        self.project_dirs = []  # working_dir labels of the containers of the project, whatever its name

    def context(self):
        return "default"

    def label_values(self, label, value, wanted):
        return self.project_dirs

    @staticmethod
    def image_id(name):
        return "sha256:" + name.replace(":", "-")

    def inspect_image(self, ref):
        ref = next((name for name in self.local if self.image_id(name) == ref), ref)  # an id or a name
        if ref not in self.local:
            raise DockerError(f"No such image: {ref}")
        return {"Id": self.image_id(ref), "Config": {"User": self.users.get(ref, "")},
                "RepoDigests": self.digests.get(ref, [])}

    def create(self, args):
        self.calls.append(("create", args))
        image = args[-1]
        if image not in self.local:
            return 1, None
        container = f"c{len(self._containers) + 1}"
        self._containers[container] = image
        self.created.append((image, args))
        return 0, container

    def inspect_container(self, ref):
        image = self._containers[ref]
        config = {"Image": image, "User": self.users.get(image, "")}
        return {"Id": ref, "Image": self.image_id(image), "Config": config}

    def read_file(self, container, path):
        return {"/etc/passwd": PASSWD, "/etc/group": GROUP}[path]

    def remove(self, container):
        self.calls.append(("remove", container))
        self._containers.pop(container, None)


class FakeDocker(Executing):
    """Records calls. `image_user` is the image's USER; `container_user` is what the container reports."""

    def __init__(self, image_user="", container_user=None, image="img", command=None, passwd=PASSWD,
                 group=GROUP, open_stdin=False, create_code=0, context="default", image_missing=False,
                 info_extra=None, repo_digests=None, image_env=None, env_file=None):
        self.image_user = image_user
        self.container_user = image_user if container_user is None else container_user
        self.image, self.command = image, command or []
        self.passwd, self.group = passwd, group
        self.open_stdin, self.create_code, self.current_context = open_stdin, create_code, context
        self.image_missing = image_missing
        self.info_extra = info_extra or {}  # for example {"Mounts": [{"Type": "bind"}]}
        self.repo_digests = repo_digests or []  # where the image was pulled from
        self.image_env = image_env or []        # the image's ENV, as NAME=value
        self.env_file = env_file or []          # what an --env-file of the command line would add
        self.env = [*self.image_env, *self.env_file]
        self.calls = []
        self.executed, self.forwarded = [], []

    def create(self, args):
        self.calls.append(("create", args))
        if "--pull=never" in args and self.image_missing:
            return 1, None
        self.host_config = {"CapDrop": [], "SecurityOpt": []}  # what the daemon records of the options
        self.env = [*self.image_env, *self.env_file]
        for position, arg in enumerate(args):
            if arg == "-e":
                self.env.append(args[position + 1])
            if arg.startswith("--user="):
                self.container_user = arg[len("--user="):]
            elif arg.startswith("--cap-drop="):
                self.host_config["CapDrop"].append(arg[len("--cap-drop="):])
            elif arg.startswith("--security-opt="):
                self.host_config["SecurityOpt"].append(arg[len("--security-opt="):])
        return (self.create_code, "cid1" if self.create_code == 0 else None)

    def inspect_container(self, ref):
        self.calls.append(("inspect", ref))
        if ref == "gone":
            raise DockerError("No such container: gone")
        host = {**getattr(self, "host_config", {}), **(self.info_extra.get("HostConfig") or {})}
        return {"Id": "id-" + ref, "Image": "sha256:abc", "Config": {
            "Image": self.image, "Cmd": self.command, "User": self.container_user,
            "OpenStdin": self.open_stdin, "Env": self.env}, **self.info_extra, "HostConfig": host}

    def inspect_image(self, ref):
        return {"Config": {"User": self.image_user, "Env": self.image_env}, "RepoDigests": self.repo_digests}

    def read_file(self, container, path):
        return {"/etc/passwd": self.passwd, "/etc/group": self.group}[path]

    def start(self, container, attach, interactive, detach_keys):
        self.calls.append(("start", container, attach, interactive, detach_keys))
        return 42

    def remove(self, container):
        self.calls.append(("remove", container))

    def context(self):
        return self.current_context

    def label_values(self, label, value, wanted):
        return []

    def names(self):
        return [call[0] for call in self.calls]


class Recorder:
    """What docker was asked to run: compose commands, and the config file each one would read."""

    def __init__(self):
        self.children = []
        self.configs = []   # the file behind -f at the moment of each child command
        self.captured = []


def make_image_ctx(images=None, ctx=None, **compose):
    """(imagedecision.Context, recorder), with images as its docker, which also runs the compose commands
    (fake_compose takes compose).
    """
    images = images if images is not None else FakeImages()
    recorder = fake_compose(images, **compose)
    ctx = ctx or imagedecision.Context(images, rules(), make_runtime(me=(1000, 1000), docker=images))
    return ctx, recorder


def fake_compose(images, active=("web",), codes=None, on_child=None, reads=None, project=None):
    """Makes images run the compose commands, and returns the Recorder of what they were.

    codes: exit code by compose subcommand, default 0; the last child is `up` etc.

    reads: changes the config `docker compose config` reports for a generated file (a compose that
    reads it differently from what was written).

    project: the compose file of the project, which `docker compose config` reads when the command names
    no file with -f.
    """
    recorder = Recorder()
    codes = codes or {}

    def run_child(cmd):
        recorder.children.append(cmd)
        recorder.configs.append(read_config(cmd))
        if on_child:
            on_child(cmd)
        subcommand = next((token for token in cmd[2:] if token in SUBCOMMANDS), None)
        code = codes.get(subcommand, 0)
        if subcommand in ("pull", "build") and code == 0:
            images.local.update(images.users)  # what was pulled or built is there afterwards
        return code

    def capture(cmd):
        recorder.captured.append(cmd)
        if "--format" in cmd:  # config --format json: what compose makes of the project or the generated file
            path = cmd[cmd.index("-f") + 1] if "-f" in cmd else project
            try:
                config = _read_json(path)
            except ValueError:
                return subprocess.CompletedProcess(cmd, 1, "", "bad yaml")
            if reads and path != project:
                config = reads(config)
            return subprocess.CompletedProcess(cmd, 0, json.dumps(config), "")
        return subprocess.CompletedProcess(cmd, 0, "\n".join(active) + "\n", "")

    images.run_child, images.capture = run_child, capture
    return recorder


def compose_project(directory, project, images=None, settings=None, **compose):
    """(runtime, recorder) for a compose project in directory, whose compose.yaml holds the config project.

    The runtime runs from directory with settings (default: the defaults), and images (default: none) as
    its docker, which runs compose (fake_compose takes compose).
    """
    path = os.path.join(directory, "compose.yaml")
    with open(path, "w") as f:
        json.dump(project, f)
    images = images if images is not None else FakeImages()
    recorder = fake_compose(images, project=path, **compose)
    runtime = make_runtime(docker=images, cwd=str(directory), settings=settings or config.Config())
    return runtime, recorder


def read_config(cmd):
    """The config compose would make of the file behind -f."""
    raw = read_raw(cmd)
    return None if raw is None else json.loads(raw)


def _read_json(path):
    if path is None or not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def read_raw(cmd):
    """The text of the file behind -f, as written."""
    if "-f" not in cmd or not os.path.exists(cmd[cmd.index("-f") + 1]):
        return None
    with open(cmd[cmd.index("-f") + 1]) as f:
        return f.read()

