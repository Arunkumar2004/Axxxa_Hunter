# XXE — XML External Entity Injection (xxe)

An XML parser resolving attacker-defined external entities, giving file read,
SSRF, or OOB exfiltration. Confirm with a named file read or a collaborator callback.

## Checklist
- Find XML entry points: SOAP endpoints, SAML, RSS/Atom imports, SVG/DOCX/XLSX/PDF uploads, `Content-Type: application/xml` or `text/xml` bodies, and APIs that also accept XML when asked.
- Baseline the parser: submit well-formed then malformed XML and watch error behaviour to confirm server-side parsing.
- Classic file read via internal DTD + external entity: define `<!ENTITY xxe SYSTEM "file:///etc/passwd">` and reference `&xxe;` in a reflected element.
- Windows/variant targets: `file:///c:/windows/win.ini`, and `php://filter/convert.base64-encode/resource=...` to read source containing XML-breaking characters.
- SSRF via XXE: point the entity at an internal URL or cloud metadata (`http://169.254.169.254/latest/meta-data/`) to reach internal services.
- Blind/OOB XXE: host an external DTD that defines a parameter entity exfiltrating file contents to your collaborator (`%remote;%send;`) when nothing is reflected.
- Error-based OOB: craft a parameter entity that forces file content into a parse-error message when outbound HTTP is blocked.
- Parameter-entity technique for non-reflectable data, and `XInclude` when you control only part of the document (`<xi:include href=... parse="text">`).
- Entity-expansion (billion-laughs) check for DoS exposure — report cautiously, many programs exclude DoS.
- File-format XXE: inject a crafted `[Content_Types].xml`/`.rels` into an OOXML (DOCX/XLSX) upload, an SVG with a DOCTYPE, or an XMP block in an image the server parses.
- SAML-specific: XXE inside the assertion when the SP parses it before signature validation.
- Confirm with a concrete read (your own /etc/passwd or a named file) or an OOB callback; keep payloads non-destructive and in scope.

## Bypasses
- `php://filter` base64 wrapper to read files whose raw bytes would break the XML parse.
- External/parameter-entity (OOB) DTD when internal general entities are forbidden or nothing is reflected.
- `UTF-16`/`UTF-7` or alternate encodings and a BOM to slip a DOCTYPE past a naive `<!DOCTYPE` string filter.
- XInclude when the DOCTYPE is stripped but the parser still processes includes.
- Nested/parameter entities via an external DTD to bypass a "no external entity in document" check.
- Switch content-type to XML on an endpoint that also accepts JSON, reaching a looser XML parser.

## Kill rules
- The parser rejects or ignores the DOCTYPE/entity (entities come back empty or literal) — external entities are disabled.
- A 500 XML error with no file content, no OOB callback, and no error-based leak — unproven.
- Only entity-expansion/DoS is shown and the program excludes DoS.
- The SSRF via XXE reaches only an external host you control, nothing internal.
- The processed XML is fully attacker-local (client-side) with no server parsing.
- The endpoint/file pipeline is out of scope or a documented sandbox.
