# JWT Attacks (jwt)

Forging or tampering a JSON Web Token the server will accept. Confirm a concrete
effect (privilege escalation, impersonation, auth bypass) with a token the server
verifies, not merely a token you can craft.

## Checklist
- Collect tokens and decode header+payload (base64url); note `alg`, `kid`, `jku`/`jwk`/`x5u`, `typ`, and sensitive claims (`sub`, `role`, `admin`, `exp`, `aud`, `iss`).
- `alg:none` / unsigned: set header `alg` to `none`/`None`/`NONE`, strip the signature (keep the trailing dot), and send a tampered payload.
- Signature-not-verified: change a claim, keep a garbage signature, and see whether the server accepts it (no verification at all).
- RS256->HS256 confusion: take the server's RSA public key (from `/jwks.json`, a cert, or recovered) and HMAC-sign the token with it as the secret, so an RS256 verifier using HS256 accepts it.
- Weak HMAC secret: offline-crack HS256/384/512 with a wordlist (jwt_tool/hashcat); if cracked, forge arbitrary claims.
- `kid` injection: path traversal/SQLi/command in `kid` to point verification at a file you control (`/dev/null`, a predictable file) or to inject a key.
- `jku`/`x5u` abuse: point the key-set URL to your host serving a public key whose private half you own, if the server fetches it without allowlisting — pair with SSRF checks.
- `jwk` header injection: embed your own public key in the token header and see whether the server trusts it to verify.
- Claim tampering for privilege/identity: flip `role`/`admin`/`sub`/`tenant`, and test `aud`/`iss` confusion across services sharing a verifier.
- Expiry/replay: use an expired token (is `exp` enforced?), replay after logout, and check whether `nbf`/`iat` are validated.
- Cross-environment confusion: a token from a staging/other-tenant issuer accepted in production.
- Confirm a concrete effect (privilege escalation, impersonation, auth bypass) with a forged token the server accepts.

## Bypasses
- `alg:none` casing variants and an empty signature segment.
- RS256->HS256 key confusion using the public key as the HMAC secret.
- `kid` path traversal / injection to control which key is used (`kid: ../../dev/null` with an empty-key signature).
- `jku`/`x5u` pointing at an attacker-hosted JWKS (chain with SSRF/allowlist bypass), and a self-provided `jwk` key.
- Weak/default secret cracking offline, then re-signing.
- Nested/duplicate claims and header-parameter confusion the verifier mishandles.

## Kill rules
- The server rejects the tampered/`none`/re-signed token (401) on every variant — signature verification holds.
- You forged a token but it grants only your own existing privileges — no escalation or impersonation.
- The secret is strong and uncracked; the public key is not accepted as HMAC — confusion fails.
- `exp`/signature are enforced and the replayed/expired token is refused.
- The token is opaque/encrypted (JWE) and you demonstrate no tamper acceptance.
- The issuer/verifier/host is out of scope.
