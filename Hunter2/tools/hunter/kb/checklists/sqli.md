# SQL Injection (sqli)

User input reaching a SQL query unsafely. Prove it with a reproducible
boolean/time differential or a readable value (version, a row), not a lone error.

## Checklist
- Inventory every sink that reaches a query: search/filter/sort params, `id`/`order`/`group`, `LIMIT`/`OFFSET`, JSON fields, headers (`User-Agent`, `X-Forwarded-For`), cookies, and `ORDER BY` column names.
- Fingerprint the stack first (`.php`->MySQL, `.aspx`->MSSQL, Java/Spring->PG/Oracle) so you pick the right syntax and time function before blind testing.
- Error-based probe: inject `'`, `"`, backtick, `\`, `');--` and watch for a DB error, a 500, or a changed response — a differential, not merely an exception string.
- Boolean-based blind: compare `' AND 1=1-- -` vs `' AND 1=2-- -` (and numeric `AND 1=1` without quotes); a stable true/false content diff confirms injection.
- Time-based blind: `' AND SLEEP(5)-- -` (MySQL), `'; WAITFOR DELAY '0:0:5'-- -` (MSSQL), `' AND pg_sleep(5)-- -` (PG), `|| dbms_pipe.receive_message(('a'),5)` (Oracle); confirm the delay is reproducible and dose-dependent.
- Determine column count with `ORDER BY N` (increment until error) or `UNION SELECT NULL,NULL,...` until the shape matches.
- UNION read: once columns and a reflected position are known, pull `@@version`/`version()`, `current_user`, `database()` to prove readable data.
- Identify injection context: string (quote break-out), numeric (no quotes), `LIKE`, `IN()`, `ORDER BY` (use `CASE`/boolean, not UNION), or inside a quoted identifier.
- Second-order: store a payload via one request (profile name, address) that a different endpoint later concatenates into a query; test the consuming page.
- Stacked queries where the driver allows (`; INSERT ...`); many APIs forbid them, so prefer sub-query/UNION.
- Out-of-band for fully blind cases: MySQL `LOAD_FILE`/`INTO OUTFILE` to a UNC path, MSSQL `xp_dirtree`, Oracle `UTL_HTTP`/`UTL_INADDR` to a collaborator host.
- Single-request dump to prove impact without mass extraction: `GROUP_CONCAT` (MySQL) / `STRING_AGG` (MSSQL/PG) / `LISTAGG` (Oracle) over one sensitive table.
- ORM/NoSQL fallthrough: if the back-end is Mongo/ORM, pivot to the nosqli checklist rather than forcing SQL syntax.
- Confirm read-only and in-scope: prove with a `version()`/one-row read, do not modify data, and treat DB-to-OS escalation as out of scope unless explicitly allowed.

## Bypasses
- Inline comments splitting keywords: `SE/**/LECT`, `UN/**/ION`, and MySQL version comments `/*!50000UNION*/`.
- Case randomisation (`SeLeCt`) and keyword doubling (`SELSELECTECT`) against naive strip filters.
- Whitespace alternatives: `%0a`, `%0b`, `%0c`, `%0d`, `%a0`, `/**/`, `+` between tokens.
- Operator substitution: `OR`->`||`, `AND`->`&&`, `=`->`LIKE`/`REGEXP`, comma-less UNION via `JOIN`.
- Encoding: URL, double URL, hex literals (`0x61646d696e`), `CHAR()`/`CONCAT()` string building, unicode/full-width.
- Quote-less strings via hex or `CHAR()` when quotes are filtered or magic-quoted.
- Move the payload to a header/cookie/`ORDER BY` the WAF inspects less, and run candidates through `tools/waf_encoder.py --class sqli`.

## Kill rules
- A reflected DB error with no demonstrated data read or boolean/time control — error disclosure, not proven SQLi.
- A single 500 with no reproducible boolean or time differential — could be any input-validation crash.
- The delay is not dose-dependent (same lag at `SLEEP(0)` and `SLEEP(5)`) — network jitter, not time-based SQLi.
- A scanner flags a point you cannot reproduce by hand with a concrete true/false or version read — unconfirmed.
- The input is parameterised and the diff is explained by ordinary app logic (e.g. an empty result set).
- The affected query/host is third-party or out of scope, or sits behind an explicit test sandbox.
