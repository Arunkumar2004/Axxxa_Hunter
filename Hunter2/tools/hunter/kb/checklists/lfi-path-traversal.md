# LFI / Path Traversal (lfi-path-traversal)

Reading files outside the intended directory, or including them as code. A bare
read-only `/etc/passwd` is usually low; the payable finding is source/secret
disclosure or a concrete path to code execution.

## Checklist
- Target file-referencing params: `file`, `path`, `page`, `template`, `tpl`, `include`, `doc`, `view`, `download`, `load`, `src`, `dir`, `lang`, `theme`, `pdf`, `log`.
- Classify the sink first: `include`/`require` (code can execute -> RCE ceiling) vs `readfile`/`file_get_contents`/download (read-only -> disclosure ceiling).
- Baseline traversal on Linux: `../../../../../../etc/passwd` -> `root:x:0:0` confirms read; also try absolute `/etc/passwd` and `file:///etc/passwd`.
- Windows: `..\..\..\..\windows\win.ini` (look for `[fonts]`/`[extensions]`) and `C:\Windows\System32\drivers\etc\hosts`.
- Depth and anchoring: increase `../` depth, and when the app prefixes/suffixes a path, start inside the app's base dir then break out.
- Extension-append defeat: if the sink adds `.php`, use `php://filter/convert.base64-encode/resource=config.php` to read source without the literal file name.
- Source/secret disclosure via `php://filter` to grab `config.php`/`wp-config.php`/`.env`/JWT keys — the usual payable escalation from a read primitive.
- include()-to-RCE paths: PHP filter-chain (iconv) to synthesise PHP with no upload; log poisoning (`User-Agent` -> include `access.log`); `.user.ini`/`.htaccess` auto_prepend with an image polyglot; `data://`/`expect://`/`php://input`; session-file inclusion; `/proc/self/environ`.
- Interesting read targets: `/proc/self/cmdline`, `/proc/self/environ`, app config, SSH keys, cloud creds, framework secrets, `web.xml`/`WEB-INF` (Java), `.git/config`.
- Wrapper/scheme sweep where supported: `php://filter`, `data://`, `expect://`, `zip://`, `phar://` (which also reaches deserialisation).
- Confirm the exact file and keep it benign; if the sink is include()+filter reachable, demonstrate the filter-chain RCE as the real severity rather than reporting "info disclosure".
- Bound and stay in scope: read only what proves impact; do not exfiltrate mass data.

## Bypasses
- Encode the traversal: `%2e%2e%2f`, `..%2f`, `%2e%2e/`, and double-encode `%252e%252e%252f` to survive one decode pass.
- Nested/self-referencing sequences against naive `str_replace('../','')`: `....//`, `..././`, `....\/`.
- Backslash and parser normalisation on Windows/Java: `..\..\`, `....\\`.
- Overlong/unicode dots and slashes: `%c0%ae%c0%ae%c0%af`, full-width `。。/` (U+3002/U+FF0E).
- Null byte (legacy PHP<5.3.4/old Java) `...%00.png` and `?`/`#` truncation `...web.xml%3f` to drop an appended suffix.
- Wrapper instead of traversal: `php://filter/.../resource=` reads source even when path filters block `../` and an extension is appended.
- Path-prefix anchoring that starts with the allowed base dir to defeat a `startswith()` check with no `realpath()`.

## Kill rules
- Read-only LFI returning only `/etc/passwd` or `win.ini` with no secret, no source, and no exec path — usually Info/low, needs a named escalation.
- The traversal stays inside the intended directory / is canonicalised away — no files outside scope reached.
- You can name no sensitive file it unlocks and the sink is a pure download of public assets.
- The include is sandboxed/allowlisted and neither wrappers nor traversal reach anything useful.
- The target is third-party or out of scope.
- The leak duplicates a known, already-exposed path with no new impact.
