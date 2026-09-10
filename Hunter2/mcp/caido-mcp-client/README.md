# Caido MCP Integration

Connect Claude Bug Bounty to [Caido](https://caido.io) — the lightweight web security auditing toolkit — via the community [`caido-mcp-server`](https://github.com/c0tton-fluff/caido-mcp-server).

Caido is a Burp Suite alternative built in Rust. If you already use Caido as your daily proxy, this integration gives the hunting agent live visibility into your traffic the same way the Burp MCP client does.

## What You Get

With Caido MCP connected, the tool can:

- **Read proxy history** — every request/response captured by Caido
- **Send requests via Replay** — get status, headers, body returned inline
- **Send requests in parallel** — up to 50 per batch (BAC sweeps, parameter fuzzing, endpoint sweeps)
- **Access fuzzing sessions, results, and payloads**
- **Search/filter traffic** — by host, method, status, content type
- **Read project state** — projects, scopes, sitemaps

The MCP server auto-redacts `Authorization`, `Cookie`, `Set-Cookie`, and API-key headers from anything it returns to the model, so credentials don't leak into the LLM context.

## Setup (5 minutes)

### Step 1: Install the Caido MCP server

The Hunter project bundles the Windows bridge at
`tools/bin/caido-mcp-server.exe`. Other platforms can download the matching
binary from the [project releases](https://github.com/c0tton-fluff/caido-mcp-server/releases).

### Step 2: Authenticate the local bridge

Start Caido and open a workspace, then run this from the Hunter project folder:

```powershell
$env:CAIDO_URL = "http://127.0.0.1:8080"
tools/bin/caido-mcp-server.exe login
```

### Step 3: Start OpenCode

The project root `opencode.json` already points to the bundled bridge. Start
OpenCode from the Hunter project folder.

### Step 4: Verify connection

Run `opencode mcp list`, then start a hunt:

```
/hunt target.com
```

If Caido MCP is connected, the agent will pull from your proxy history and reference traffic you've already captured.

## Burp + Caido side-by-side

You can run both MCP servers at the same time. The hunting agent will use whichever has traffic for the current target. Most users pick one — leave the other entry out of `mcpServers` to avoid duplicate tool surfaces.

## Without Caido

All commands work without the Caido MCP. The tool falls back to:

- `curl` for HTTP requests (you provide auth headers manually)
- Manual request/response pasting for validation
- `webhook.site` or Interactsh for OOB testing

## Troubleshooting

| Problem | Fix |
|---|---|
| "Caido MCP not connected" | Check Caido is running and `CAIDO_URL` is reachable (`curl $CAIDO_URL/health`) |
| "Unauthorized" | Start Caido and re-run `tools/bin/caido-mcp-server.exe login` |
| "No proxy history" | Browse the target through Caido first — proxy history is what you've captured |
| "Too many requests" | The MCP server caps parallel batches at 50; reduce batch size in your prompt |
