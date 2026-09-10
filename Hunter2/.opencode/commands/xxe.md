---
description: Scan an XML/SOAP endpoint for XXE - internal-entity expansion, error-based file disclosure, and blind OOB external entities. Usage: /xxe <url> [--oob http://x.oast.fun] [--cookie "s=..."]
---

# /xxe

Test XML-accepting endpoints for XML External Entity injection. Safe-by-default:
starts with non-destructive internal-entity expansion, escalates to error-based
disclosure and (opt-in) blind OOB.

## Usage

```
/xxe https://target.com/api/xml
/xxe https://target.com/soap --oob http://abc.oast.fun
/xxe -l recon/target.com/urls/xml.txt --cookie "s=..." --json
```

Run directly:

```bash
tools/xxe_scanner.py https://target.com/api/xml --oob http://abc.oast.fun
```

## Detection ladder

1. Parses XML? well-formed vs malformed response differ -> candidate.
2. Internal entity expands -> entity processing ON (MEDIUM).
3. Error-based SYSTEM entity -> parser leaks file contents/paths (HIGH/MEDIUM).
4. Blind OOB (`--oob`) -> parameter-entity payload to your interactsh host;
   confirm the callback (`tools/oob_listener.py` / interactsh-client).

## Severity

- **HIGH** - file contents disclosed, or OOB payload delivered (confirm callback).
- **MEDIUM** - internal entity expands, or a filesystem path leaks in an error.
- **LOW** - parses XML but no expansion (hardened parser) - retry parameter entities.

## Chain

XXE file read -> source/secret disclosure -> RCE via config/keys. Blind XXE ->
SSRF into internal services.
