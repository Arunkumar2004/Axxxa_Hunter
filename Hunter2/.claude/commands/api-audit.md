---
description: Full API security audit against OWASP API Top 10 2023. Usage: api-audit <base-url> [--auth bearer TOKEN] [--spec url]
---

# /api-audit

Audit an API surface for authorization, auth, and misconfiguration bugs.

## Run This

```bash
# Discover spec + run core probes (BOLA, BFLA, mass assignment, missing auth):
python tools/api_security_scanner.py <base-url>

# With an authenticated session:
python tools/api_security_scanner.py <base-url> --auth bearer <TOKEN>

# If an OpenAPI/Swagger spec URL is known:
python tools/api_security_scanner.py <base-url> --spec https://target.com/swagger.json

# Follow with targeted IDOR / mutation / JWT:
python tools/h1_idor_scanner.py <request-template> --id-range 1 100
python tools/h1_mutation_idor.py <url> --method PUT --json '{"id":1}'
python tools/jwt_scanner.py <token>
bash   tools/graphql_audit.sh <url>
```

## Workflow

1. `api_security_scanner.py` finds spec + endpoints + probes (BOLA by ID swap, BFLA by method/path escalation, BOPLA via extra fields, missing auth).
2. If it reports candidates, confirm each manually with a second identity (BOLA evidence = foreign object data returned).
3. Route: GraphQL endpoint → `graphql-audit`; JWT → `jwt-scan`; SSRF param → `ssrf` skill; login flow → `auth-hunt`.

## Rules

- Two-identity BOLA proof > single-account ID guessing.
- Mass assignment valid only if change persists (check twice).
- Never test against accounts you don't own.

## Output

Write findings to `findings/<target>/api-audit-<date>.json` via lead board (`python tools/lead_board.py ingest <target> --route api`), then `validate` each.
