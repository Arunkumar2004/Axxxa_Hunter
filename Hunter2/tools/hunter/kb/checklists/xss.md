# XSS — Cross-Site Scripting (xss)

Attacker-controlled script executing in a victim's browser on the target origin.
Confirm execution in the right context; a reflected-but-encoded value is not XSS.

## Checklist
- Enumerate inputs and their reflection/storage contexts: query/body/path/header/cookie params, and where each lands (HTML body, attribute, JS string, URL, CSS, JSON-in-HTML).
- Fire a unique canary (`hunterCANARY123`) and grep the response to find exactly where and how it is reflected before choosing a payload.
- Determine context and break out accordingly: HTML text (`<svg onload=...>`), attribute (`" autofocus onfocus=...`), JS string (`';alert(1)//`), URL/href (`javascript:alert(1)`), CSS, or JSON.
- Reflected XSS: confirm execution with a benign `alert(document.domain)`/`print()`, noting whether it fires without extra interaction.
- Stored XSS: submit via one surface (comment, profile, filename, support ticket) and confirm execution when a different/privileged user views it — the high-impact variant.
- DOM XSS: trace `location`/`document.URL`/`referrer`/`postMessage`/`localStorage` sources into sinks `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout(str)`, `element.src`, `location=`.
- postMessage/CSWSH overlap: an `addEventListener('message')` handler with a weak/absent `event.origin` check feeding a DOM sink is XSS reachable cross-origin.
- Attribute-context tricks: escape unquoted attributes with whitespace/`>`, use handlers needing no quotes, and `autofocus`/`accesskey` to self-trigger.
- Markup-free JS contexts: template literals, inline event handlers, and JSONP callbacks (`?callback=alert`).
- mXSS / sanitiser bypass: feed markup that mutates after DOMPurify/innerHTML round-trips (`<noscript>`, `<svg>`, `<math>`, `<template>`, namespace confusion).
- CSP review: read the `Content-Security-Policy`; find `unsafe-inline`, `unsafe-eval`, wildcard/allowlisted hosts, a JSONP/Angular origin, or nonce reuse that enables a bypass.
- Filter probing: test which characters survive (`<`,`>`,`"`,`'`,`/`,`(`,backtick), then build a payload only from the allowed set.
- Blocked-`<script>` payloads: `<svg onload=eval(atob('...'))>`, `<img src=x onerror=...>`, `<svg><animate onbegin=... >`.
- Chain the impact: cookie/token theft (if not HttpOnly), CSRF-token exfil, keylogging a login form, or an account action from the victim's session.
- Prove and bound it: keep the PoC benign, confirm the executing origin is the target, and note whether it is self-XSS only.

## Bypasses
- Tag/handler variety when `<script>` is filtered: `<svg onload>`, `<img onerror>`, `<body onload>`, `<details ontoggle>`, `<svg><animate onbegin>`.
- Encoding layers: HTML entities (`&#x61;`), URL/double-URL, JS unicode escapes (`a`), and base64 via `atob()`.
- Case mixing, backtick template literals, and splitting keywords the filter strips (`<scr<script>ipt>`).
- CSP bypass via `unsafe-inline`, an allowlisted JSONP/Angular/CDN origin, or a `base-uri`/dangling-markup trick.
- mXSS through sanitiser mutation (`<noscript>`, `<template>`, SVG/MathML foreign content).
- Attribute break-out without quotes using whitespace, `/`, and `autofocus onfocus`; run candidates through `tools/waf_encoder.py --class xss`.

## Kill rules
- The payload is reflected but HTML-encoded (`&lt;svg&gt;`) and never executes — reflection, not XSS.
- Execution only occurs for the attacker in their own browser with no cross-user path (pure self-XSS) and no sensitive action.
- It fires only on an unsupported/legacy browser quirk the program excludes.
- The sink sits behind a correct CSP with a nonce and no bypass — injection does not run.
- It requires the victim to paste the payload into their own devtools/console — not a web vulnerability.
- The reflection is in a sandboxed iframe / different origin with no access to the target's data.
- The reflected value is in a downloadable file served with a non-renderable content-type plus `X-Content-Type-Options: nosniff`.
