"""MCP server entrypoint. Keep this file thin: registration only, no business logic.

Phase 0 ships a single `ping` tool so the Inspector can connect. Real tools arrive in Phase 1+
and must go through the full pipeline (auth -> policy -> risk -> approval -> connector -> audit).
"""

import argparse

from mcp.server.fastmcp import FastMCP

from mcp_gateway import __version__
from mcp_gateway.config import Settings
from mcp_gateway.policy import load_policy

mcp = FastMCP("mcp-gateway")


@mcp.tool()
def ping() -> str:
    """Health check. Returns the gateway version."""
    return f"mcp-gateway {__version__} ok"


def main() -> None:
    parser = argparse.ArgumentParser(prog="mcp-gateway")
    parser.add_argument("--transport", choices=["stdio", "http"], default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args()

    settings = Settings()
    load_policy(settings.gateway_policy_path)  # fail closed: refuse to start with a bad policy

    transport = args.transport or settings.gateway_transport
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.settings.host = args.host or settings.gateway_host
        mcp.settings.port = args.port or settings.gateway_port
        mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
