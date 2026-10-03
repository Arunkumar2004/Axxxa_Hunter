---
name: client-side-security
description: Use when hunting browser-side bugs - DOM XSS, prototype pollution, postMessage, CORS, CSRF, clickjacking, DOM clobbering, CSS injection, open redirect, WebSocket hijacking, browser extensions - or when the user says "DOM XSS", "prototype pollution", "postMessage", "CSRF", "CORS", "clickjacking". Includes headless-browser verification via Playwright/DOM XSS harness.
---

# Client-Side Security

Server-side is locked down? The browser is still attackable. Client-side bugs are often the chain component (XSS → ATO).

## 1. DOM XSS (highest value)

- Sinks: `innerHTML`, `document.write`, `eval`, `setTimeout('...')`, `location` (hash/query), `insertAdjacentHTML`, `outerHTML`, `srcdoc`, `$.html()`, `React dangerouslySetInnerHTML`, `v-html` (Vue), `dangerouslySetInnerHTML`.
- Sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`, URL params passed to JS.
- **Confirm with a real browser**: `python tools/dom_xss_harness.py <url>` — injects canaries into query + fragment, runs headless Chromium (Playwright), reports `[CONFIRMED]` only when the browser executes.
- Also: `browser` MCP (Playwright) for manual flows; `dalfox --dom` for candidates.

## 2. Prototype Pollution (client + server)

- Sources: `merge`, `$.extend(true, ...)`, `Object.assign`, query-to-object parsers (`?__proto__[x]=y`, `?constructor[prototype][x]=y`), JSON.parse of user input.
- Client gadgets: pollute then trigger a sink (`innerHTML`, `eval`, option values, `Object.prototype.safe`).
- Test: `fetch('/?' + '__proto__[canary]=x')` → check `window.canary` in browser console via Playwright.
- Server-side: `__proto__` in JSON body → mass assignment / auth bypass (see api-security).

## 3. postMessage

- Find `postMessage` senders/receivers in JS (`gau`, `linkfinder`, grep `addEventListener("message"`).
- Receiver without `event.origin` check → cross-origin message → chain to sink (DOM XSS, data write).
- Craft: `<iframe src="https://target.com/"><script>parent.postMessage('{"cmd":"xss"}','*')</script></iframe>` — confirm via Playwright.

## 4. CORS

- `python tools/cors_scanner.py <url>` — tests ACAO reflection, `null` origin, wildcard + credentials, `Access-Control-Allow-Credentials: true` + reflected origin.
- Report only with actual impact: sensitive authenticated data readable cross-origin.

## 5. CSRF

- Find state-changing requests without CSRF token / SameSite. Check: token not required on some methods (GET), token reusable, no Origin/Referer check, token in query.
- Generate PoC: `<form action=... method=POST><input name=...>` auto-submit page. SameSite=None cookies make CSRF possible again.

## 6. DOM Clobbering

- `<form id=x><input name=y value=z>` → `window.x.y` — used to hijack JS checks (e.g., `if (window.settings)`), CSP bypass, jQuery selectors.
- Test on pages rendering user-controlled HTML.

## 7. Clickjacking / UI Redress

- Missing `X-Frame-Options` / `frame-ancestors` on sensitive pages (account settings, payment) → clickjacking PoC (`<iframe>` overlay). Report only with meaningful action (not login pages).

## 8. Open Redirect (chain component)

- `?redirect=`, `?next=`, `?return=` → `//evil.com`, `/\evil.com`, `https:evil.com`, `%0d%0a` CRLF. Only report when chained (OAuth token leak, reset poisoning) or on auth flows.

## 9. WebSocket Hijacking

- WS endpoint with cookie auth and no `Origin` check → cross-site WS hijack: `<script>new WebSocket('wss://target/ws')</script>` → read victim messages, send as victim.

## Tools

```
python tools/dom_xss_harness.py <url>          # headless DOM XSS confirmation
python tools/cors_scanner.py <url>             # CORS
python tools/oob_listener.py                   # blind callback
python tools/validate.py "<finding>"
# browser MCP for manual Playwright sessions
```

## Validation

- DOM XSS = CONFIRMED only when headless browser actually executes the payload (or you show a manual console proof).
- Prototype pollution = CONFIRMED when `window.canary` is set and you have a gadget → sink.
- postMessage = CONFIRMED when you receive a cross-origin message AND reach a sink.
- CSRF = CONFIRMED with a working PoC page on your server (report as POSSIBLE if no PoC yet).

## References

- PortSwigger DOM XSS: https://portswigger.net/web-security/cross-site-scripting/dom-based
- Prototype pollution (HackTricks): https://book.hacktricks.wiki/en/pentesting-web/deserialization#prototype-pollution
- PostMessage security: https://book.hacktricks.wiki/en/pentesting-web/postmessage-vulnerabilities
- OWASP CSRF: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
