#!/usr/bin/env python3
"""
_minimal_mcp.py - Minimal stdio MCP server (JSON-RPC 2.0, newline-delimited).

Dependency-free. Implements initialize / notifications/initialized /
tools/list / tools/call for a dict of tool handlers.

Usage:
    from _minimal_mcp import serve
    serve(server_name, { "tool_name": {"description": "...", "inputSchema": {...}, "handler": fn} })
"""

import json
import sys

PROTOCOL_VERSION = "2024-11-05"


def _read_message():
    line = sys.stdin.readline()
    if not line:
        return None
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def _write(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def serve(server_name, tools):
    """tools: dict name -> {description, inputSchema, handler(args)->str}"""
    while True:
        msg = _read_message()
        if msg is None:
            break
        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "initialize":
            _write({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": server_name, "version": "1.0.0"},
                },
            })
        elif method == "notifications/initialized":
            pass
        elif method == "ping":
            _write({"jsonrpc": "2.0", "id": msg_id, "result": {}})
        elif method == "tools/list":
            _write({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {"tools": [
                    {"name": name, "description": t["description"],
                     "inputSchema": t.get("inputSchema", {"type": "object", "properties": {}})}
                    for name, t in tools.items()
                ]},
            })
        elif method == "tools/call":
            params = msg.get("params", {}) or {}
            name = params.get("name")
            args = params.get("arguments", {}) or {}
            tool = tools.get(name)
            if not tool:
                _write({"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32601, "message": f"unknown tool: {name}"}})
                continue
            try:
                text = tool["handler"](args)
                _write({"jsonrpc": "2.0", "id": msg_id,
                        "result": {"content": [{"type": "text", "text": str(text)}],
                                   "isError": False}})
            except Exception as exc:  # noqa: BLE001 - report to client
                _write({"jsonrpc": "2.0", "id": msg_id,
                        "result": {"content": [{"type": "text", "text": f"ERROR: {exc}"}],
                                   "isError": True}})
        else:
            if msg_id is not None:
                _write({"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32601, "message": f"method not found: {method}"}})
