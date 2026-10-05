# Insecure Deserialization (deserialization)

Untrusted bytes rebuilt into objects, letting a gadget chain reach code
execution. Fingerprint the wire format, then land a real gadget — a bare
`unserialize()` hit or a `rO0AB` blob with no demonstrated execution is not a bug.

## Checklist
- Locate deserialisation sinks: opaque cookies, hidden form fields, tokens, message bodies, caches/queues, and view-state — anything the server rebuilds into an object.
- Decode every opaque blob (base64/hex/url) and inspect the first bytes against known wire signatures before attacking.
- Java native: base64 `rO0AB` or hex `aced0005` = serialized stream -> fingerprint classpath libs (`MANIFEST.MF`, jar names, stack traces) and use ysoserial (CommonsCollections, Spring, Groovy).
- Java non-native: `XMLDecoder` XML (`<java><object class=...>`), Jackson `@class`/`enableDefaultTyping` polymorphic JSON, and JNDI/Log4Shell-style lookups via marshalsec.
- PHP: `O:`/`a:`/`s:` serialized data -> craft a POP chain (phpggc for framework gadgets), plus the `__wakeup` property-count bypass (CVE-2016-7124).
- PHP without a direct `unserialize`: `phar://` metadata deserialisation triggered by a file op on an attacker path (upload an image/phar polyglot first).
- Python: pickle (`gASV`/`\x80\x04`) -> `__reduce__` gadget; `yaml.load` without SafeLoader (`!!python/object/apply`); jsonpickle; and signed-cookie forgery (Flask/Django) once a `SECRET_KEY` leaks.
- Node: `node-serialize`/`funcster` `_$$ND_FUNC$$_` IIFE RCE; and .NET ViewState/`BinaryFormatter` (often via a leaked machineKey -> ysoserial.net).
- Blind confirmation: land an out-of-band callback (DNS/HTTP to your collaborator) or command output — never trust a 500 alone.
- Use the right generator (phpggc/ysoserial/ysoserial.net) rather than hand-rolling, matching the gadget to the libraries actually present.
- Prove RCE with a benign command, keep it non-destructive, and stay in scope.

## Bypasses
- PHP `__wakeup` count-mismatch (declare more properties than exist) to skip revalidation and keep the `__destruct`/`__toString` gadget.
- Java magic-byte avoidance: use `XMLDecoder`/Jackson/JNDI when `ac ed 00 05` is filtered on the wire.
- `phar://` trigger when there is no explicit `unserialize()` call (any file op on a user path).
- Encode the blob (base64/gzip/url) to pass a transport filter, and switch content-type to reach a different deserialiser.
- Signed-cookie re-signing once a secret/`SECRET_KEY` is recovered from a debug/leak surface.
- Gadget substitution: pick a chain for whichever vulnerable library is actually on the classpath.

## Kill rules
- A deserialisation sink or `rO0AB`/`O:`/`gASV` blob is present but you demonstrate no gadget execution, no OOB callback, and no command output.
- A 500/stack trace only, with no reproducible code execution — error, not proven RCE.
- No vulnerable gadget library is on the classpath and every chain fails.
- The data is signed/encrypted with a key you do not have and cannot recover — not forgeable.
- The deserialiser is a safe format (plain JSON into a map, `yaml.safe_load`) that instantiates no objects.
- The sink/host is out of scope.
