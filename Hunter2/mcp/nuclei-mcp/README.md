# Nuclei MCP Server

Minimal stdio MCP server wrapping the ProjectDiscovery `nuclei` binary.
Dependency-free (stdlib only). Provides:

- `nuclei_scan` — run nuclei against one target (`target`, `tags`, `severity`, `template`, `exclude`, `timeout`, `extra` args).
- `nuclei_version` — installed version / install hint.

## Setup

```bash
# nuclei binary (required)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

## OpenCode config

```json
{
  "mcp": {
    "nuclei": {
      "type": "local",
      "command": ["python", "mcp/nuclei-mcp/server.py"],
      "enabled": true
    }
  }
}
```

Already included in the repo root `opencode.json`.

## CLI test

```bash
python mcp/nuclei-mcp/server.py --mcp
# send: {"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}
```

or use the direct helper:

```bash
python -c "import sys; sys.path.insert(0,'mcp'); from nuclei_mcp_runner import nuclei_scan_handler; print(nuclei_scan_handler({'target':'example.com','severity':'critical'}))"
```
