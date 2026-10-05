# WebSocket Security / Cross-Site WebSocket Hijacking (websocket-cswsh)

A cookie-authenticated WebSocket that does not validate the handshake `Origin`,
letting an attacker page open a socket in the victim's context. Also covers
message-level authorisation and injection over the socket.

## Checklist
- Find WebSocket endpoints (`ws://`/`wss://`) from JS and network logs; note the handshake URL, subprotocols, and how auth is carried (cookie vs token).
- Check handshake `Origin` enforcement: replay the upgrade with a foreign or removed `Origin` and see whether it still connects — the core CSWSH condition.
- CSWSH: if the WS authenticates via cookies and does not validate `Origin`, an attacker page can open a cross-site socket in the victim's context and read/drive it.
- Build a CSWSH PoC: an attacker-hosted page that opens the socket, sends the app's messages, and exfiltrates the responses (sensitive data or privileged actions).
- Message-level authorisation (WS IDOR/BFLA): send client-supplied ids/actions (`{"action":"get_history","userId":...}`) to reach other users' data or admin actions over the socket.
- Injection over WS: XSS/SQLi/command payloads inside WS messages reach the same sinks — pivot to those checklists; test whether WS input is rendered in the DOM.
- Token-in-URL exposure: tokens passed in the `wss://` query string leak via logs/referrer — note as a weakness.
- Flooding/lack of message rate-limiting (report cautiously where DoS excluded).
- Confirm the socket actually carries the victim's authenticated session cross-origin and returns sensitive data, not a public feed.
- Keep the PoC benign and in scope; do not drive destructive actions over the socket.

## Bypasses
- Missing/weak `Origin` check: connect with no `Origin` or a spoofed one to establish the cross-site socket.
- Cookie-based auth with `SameSite=None`/absent so the cross-site handshake carries the session.
- Subprotocol / `Sec-WebSocket-Protocol` tricks and handshake header manipulation.
- Client-supplied ids/actions in messages to reach other objects (WS BOLA) when the HTTP API is guarded.
- Reuse a token observed in the handshake URL from logs/referrer.

## Kill rules
- The handshake validates `Origin` and rejects cross-site connections — no CSWSH.
- Auth is via a bearer token the attacker page cannot read (not cookie-based) — a cross-site page cannot authenticate.
- The socket only streams public, non-sensitive data and exposes no privileged action.
- Cookies are `SameSite=Strict`/`Lax` so the cross-site handshake is unauthenticated.
- The WS IDOR returns only your own data.
- The endpoint is out of scope.
