"""End-to-end over real stdio, the way an editor actually talks to this.

Everything else tests Python functions. This launches the server as a
subprocess and drives it with the MCP client, which is the only way to catch
transport-level breakage — a bad entry point, a schema the SDK rejects, or an
`instructions` string that never reaches the client.

That last one is worth a test of its own. `instructions` is the entire
mechanism by which the assistant calls these tools unprompted, and it is
invisible: if it silently stopped being transmitted, every other test here
would still pass while the product quietly stopped working.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

PKG_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = PKG_ROOT.parents[1] / "demo-iac-pr" / "main.tf"

SERVER = StdioServerParameters(
    command=sys.executable,
    args=["-c", "from sovereign_mcp.server import main; main()"],
    cwd=str(PKG_ROOT),
)


@pytest.mark.anyio
async def test_server_speaks_mcp_over_stdio():
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()

            assert init.server_info.name == "sovereign"
            # The string that makes the assistant use this without being asked.
            assert init.instructions, "server sent no instructions"
            assert "scan_terraform" in init.instructions
            assert "WITHOUT BEING ASKED" in init.instructions

            tools = {t.name for t in (await session.list_tools()).tools}
            assert tools == {
                "scan_terraform",
                "explain_finding",
                "apply_fixes",
                "secure_template",
                "check_compliance",
                "framework_coverage",
                "org_requirements",
                "org_status",
            }


@pytest.mark.anyio
async def test_scan_round_trips_through_the_transport():
    if not FIXTURE.is_file():
        pytest.skip("demo fixture not available")

    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "scan_terraform",
                {"files": {"main.tf": FIXTURE.read_text(encoding="utf-8")}},
            )

            assert not result.is_error, result.content
            data = result.structured_content
            assert data["findings_count"] > 0
            assert data["summary"]["critical"] >= 2
            assert data["findings"][0]["severity"] == "Critical"


@pytest.mark.anyio
async def test_template_round_trips_through_the_transport():
    async with stdio_client(SERVER) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                "secure_template", {"resource_type": "aws_s3_bucket"}
            )

            assert not result.is_error, result.content
            assert "block_public_acls" in result.structured_content["terraform"]
