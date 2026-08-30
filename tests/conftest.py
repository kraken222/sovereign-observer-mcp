import pytest


@pytest.fixture(scope="session")
def anyio_backend():
    """Run the async stdio tests on asyncio only (no trio dependency)."""
    return "asyncio"
