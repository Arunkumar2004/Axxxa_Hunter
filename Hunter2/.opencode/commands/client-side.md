---
description: Client-side hunt - DOM XSS, prototype pollution, postMessage, CORS, CSRF, clickjacking, WS hijacking. Usage: client-side <url> [--dom|--proto|--postmessage|--cors|--csrf]
---

# /client-side

Hunt browser-side vulnerabilities with headless verification.

## Run This

```bash
# DOM XSS confirmation (headless Chromium - only [CONFIRMED] when the browser executes):
python tools/dom_xss_harness.py <url>

# CORS misconfig:
python tools/cors_scanner.py <url>

# Prototype pollution (client): 
#   fetch('<url>/?' + '__proto__[canary]=x') -> check window.canary in Playwright
# Server-side: __proto__ in JSON body -> api-security skill

# postMessage: grep JS for addEventListener('message' + postMessage:
#   gau <url> | linkfinder | grep -i "postmessage\|message.*origin"
```

## Workflow

1. DOM XSS: `dom_xss_harness.py` → confirmed candidates; manual follow-up via `browser` MCP.
2. CORS: `cors_scanner.py` → reflected ACAO + credentials = High if sensitive data readable.
3. Prototype pollution: pollute → find gadget → sink (only report with a working gadget chain).
4. postMessage: receiver without `event.origin` check → cross-origin message → sink.
5. CSRF: state-changing request without token/SameSite → PoC page (report as POSSIBLE until PoC works).
6. Clickjacking: missing frame-ancestors on sensitive action pages.

## Rules

- DOM XSS = CONFIRMED only with headless browser execution (not just candidate).
- No logging into other users' sessions; use own test accounts.

## Output

`findings/<target>/client-<date>.md`; validate each.
