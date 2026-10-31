import pytest


@pytest.fixture(autouse=True)
def terse_messages():
    """Messages show the facts only, unless a test asks for the helpful part with helpful()."""
    from dockscreen import messages
    messages.set_helpful(False)
    yield
    messages.set_helpful(False)


@pytest.fixture
def helpful():
    from dockscreen import messages
    messages.set_helpful(True)


@pytest.fixture(autouse=True)
def local_daemon(monkeypatch):
    """Whatever daemon the developer's shell points at, tests talk to the default local one."""
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("DOCKER_CONTEXT", raising=False)


@pytest.fixture
def runtime():
    """The Runtime of fakes.make_runtime: the defaults, and a docker with no images."""
    from fakes import make_runtime
    return make_runtime()


@pytest.fixture
def forwarded(runtime):
    """The argv lists that runtime's docker handed to docker compose."""
    return runtime.docker.forwarded


@pytest.fixture(autouse=True)
def unwrapped_reports(monkeypatch):
    """Report lines stay whole, whatever terminal runs the tests: COLUMNS below the minimum turns
    wrapping off. Tests of the wrapping set the width themselves."""
    monkeypatch.setenv("COLUMNS", "10")
