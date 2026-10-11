import pytest

from fixtures import evil_server


@pytest.fixture(autouse=True)
def reset_evil_fixture():
    """The evil server mutates itself (rug pull); start every test from the poisoned state."""
    evil_server.reset()
    yield
