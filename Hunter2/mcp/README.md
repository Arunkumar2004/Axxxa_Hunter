# MCP

MCP (Model Context Protocol) server integrations — all pre-wired in the repo
root `opencode.json` for OpenCode.

| Integration | Purpose | Status |
|:---|:---|:---|
| `caido-mcp-client/` | Caido proxy integration — request interception + active scan | ✅ in opencode.json |
| `burp-mcp-client/` | Burp Suite proxy integration — pipe agent requests through Burp | ✅ in opencode.json (needs `BURP_MCP_JAR`) |
| `hackerone-mcp/` | HackerOne public API — Hacktivity, program stats, scope/policy | ✅ real MCP server (`--mcp` stdio) |
| `nuclei-mcp/` | Nuclei template scanner via MCP (`nuclei_scan`) | ✅ new, stdlib only |
| `shodan` (external) | Shodan exposure intel — `npx @burtthecoder/mcp-shodan` | ✅ in opencode.json (needs `SHODAN_API_KEY`) |
| `browser` (external) | Playwright MCP — headless browser automation | ✅ in opencode.json (`npx @playwright/mcp`) |

## OpenCode

Everything is configured in the repo root `opencode.json`. Required env vars
(see `docs/auth.example.json` / your shell profile):

- Caido: start Caido, then run `tools\bin\caido-mcp-server.exe login` once per user; URL defaults to `http://127.0.0.1:8080`
- `BURP_MCP_JAR` — absolute path to `mcp-proxy-all.jar` for burp
- `SHODAN_API_KEY` — for shodan

MCP server health: `opencode mcp list`

## Claude Code (legacy)

Claude Code configs live in each `mcp/*/` folder (`config.json`).
