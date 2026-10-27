from mcp_gateway import __version__
from mcp_gateway.server import ping


def test_ping() -> None:
    assert __version__ in ping()
