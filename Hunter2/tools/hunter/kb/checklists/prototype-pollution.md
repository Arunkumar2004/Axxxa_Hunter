# Prototype Pollution (prototype-pollution)

Injecting `__proto__`/`constructor.prototype` keys into a merge/clone so a
polluted property reaches a sink. Pollution alone is low; it pays only via a
concrete gadget (XSS, RCE, privilege, behaviour change).

## Checklist
- Identify merge/clone/parse sinks: `Object.assign`/deep-merge libraries, query-string parsers, JSON into object merges, config loaders — anywhere attacker keys reach object properties.
- Client-side source hunt: URL, hash, query, `postMessage`, and JSON that flows into jQuery `$.extend(true,...)`, lodash `merge`/`set`, or a manual recursive merge.
- Inject the pollution keys: `__proto__[x]=y`, `constructor[prototype][x]=y`, and JSON `{"__proto__":{"x":"y"}}` / `{"constructor":{"prototype":{"x":"y"}}}`.
- Confirm pollution: set a benign marker (`__proto__[hunterpp]=1`) and read it back on an unrelated object (`({}).hunterpp`) in the page/console.
- Client gadget to XSS: find a property the app reads from the prototype and uses in a sink (`src`, `innerHTML`, a template option, `srcdoc`, sanitiser config) to escalate to DOM XSS.
- Server-side (Node): pollute via JSON body/query into a merge, then trigger a gadget — spawn args, template-engine options, a `status`/header property, or a flag the app reads.
- Server gadget to RCE: known gadgets in Express/EJS/Pug/Handlebars/child_process that read a polluted prototype property (`shell`, `env`, `NODE_OPTIONS`).
- Auth/logic gadget: pollute a default like `isAdmin`/`role`/`authenticated` that the app later reads as a fallback.
- DoS gadget (report cautiously): polluting a property that crashes request handling.
- Parameter formats: bracket (`a[__proto__][b]=1`), dotted (`a.__proto__.b=1`), and JSON — try each parser.
- Confirm a concrete downstream impact (XSS/RCE/privilege/behaviour change), not merely that `{}.polluted` is set.

## Bypasses
- Key variants: `__proto__`, `constructor.prototype`, and nested/dotted/bracket encodings to beat a single-key blacklist.
- Encoded keys (`__pro__proto__to__`, unicode, double-encoding) against naive string strips that run once.
- Switch parser: send JSON where bracket is filtered, or query-string where JSON is filtered.
- Array vs object wrapping to reach a merge path the sanitiser misses.
- Pollute through `postMessage`/hash on the client when body params are filtered.

## Kill rules
- You can set `{}.polluted` but there is no gadget — no XSS, RCE, privilege, or behaviour change results.
- The library is prototype-pollution-safe (null-proto objects, `Object.create(null)`, Map) and the key is ignored.
- The pollution is confined to your own session/page with no cross-user or server effect.
- Only a self-DoS/crash on an excluding program.
- The marker reads back only inside your devtools with no reachable sink.
- The sink/host is out of scope.
