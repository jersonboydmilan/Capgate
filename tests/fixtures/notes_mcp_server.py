"""A real MCP server (official SDK, stdio) standing in for a consequential system.

Requires NOTES_TOKEN (its "credential") and records every side effect to
NOTES_LEDGER, so tests can prove what actually happened upstream.
"""

import json
import os
import sys

from mcp.server.mcpserver import MCPServer

if not os.environ.get("NOTES_TOKEN"):
    sys.exit("NOTES_TOKEN missing: refusing to start without a credential")

LEDGER = os.environ["NOTES_LEDGER"]
server = MCPServer("notes")


def record(op: str, **fields) -> None:
    with open(LEDGER, "a") as fh:
        fh.write(json.dumps({"op": op, **fields}) + "\n")


@server.tool(description="Write a note.")
def write_note(title: str, text: str) -> str:
    record("write", title=title, text=text)
    return f"saved {title}"


@server.tool(description="Read a note.")
def read_note(title: str) -> dict:
    return {"title": title, "text": f"contents of {title}"}


@server.tool(description="Delete a note permanently.")
def delete_note(title: str) -> str:
    record("delete", title=title)
    return f"deleted {title}"


@server.tool(description="Publish a note to the public site.")
def publish_note(title: str) -> str:
    record("publish", title=title)
    return f"published {title}"


if __name__ == "__main__":
    server.run("stdio")
