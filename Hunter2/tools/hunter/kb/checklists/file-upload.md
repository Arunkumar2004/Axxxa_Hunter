# Malicious File Upload (file-upload)

Uploading a file that executes as code, carries stored XSS/XXE, or escapes its
directory. Prove the file actually runs or fires in a victim context.

## Checklist
- Map upload surfaces and what happens next: avatar, attachment, import, document/image processors, and whether the file is stored web-accessible, parsed, or converted.
- Determine the storage path and naming: can you reach the uploaded file by URL, is the name preserved, and is the directory executable?
- Executable-extension probe: upload `shell.php`, then variants `.phtml`, `.php5`, `.phar`, `.pHp`, `.asp`, `.aspx`, `.jsp`, `.jspx` and check whether any is served as code.
- Double/null/space extensions: `shell.php.jpg`, `shell.jpg.php`, `shell.php%00.jpg`, `shell.php;.jpg`, `shell.php .` to defeat naive extension checks.
- Content-Type spoof: keep a dangerous body but send `Content-Type: image/jpeg`; conversely, a valid extension with a script body.
- Magic-byte polyglot: prepend `GIF89a;` / JPEG magic bytes to a script payload so magic-byte validators pass while the file still executes.
- SVG/HTML/XML uploads: stored XSS via `<svg><script>`, and XXE via SVG/DOCX/XLSX if the server parses them.
- Image-library exploits: ImageTragick/Ghostscript via a crafted image, and XMP/EXIF payloads that reach a processor.
- Path/overwrite tricks: filename traversal `../../` (zip-slip in archives) to overwrite config/other users' files or write outside the upload dir.
- `.htaccess`/`.user.ini` upload to make an otherwise-static directory execute your payload or auto-prepend a shell (chain with LFI).
- Multipart parser confusion: boundary tricks, duplicated/last-wins `filename`, `Content-Disposition` sub-param injection, a `charset=utf-16le` part, and RFC 2231 `filename*=`.
- Client-only validation: if the extension/type check is client-side, replay the raw request directly to the server.
- Confirm real impact: execute the uploaded shell (benign `id`/`phpinfo`), fire the stored XSS in a victim context, or read a file via the parser, then auto-delete what you created.

## Bypasses
- Extension evasions: alternate executable extensions, case mixing, double extension, trailing dot/space/`;`, null byte.
- MIME/magic-byte spoof: fake `Content-Type` or prepend image magic bytes to a script (polyglot).
- Multipart quirks: simplified/duplicated boundaries, `charset=utf-16le` part decoding, `Content-Disposition` injection, `filename*=utf-8''` and MIME-Base64 filenames.
- Content-type switch and last-wins duplicate parts so the validator and the file store disagree.
- Config-file upload (`.htaccess`, `.user.ini`, `web.config`) to turn a static directory executable.
- Archive path traversal (zip-slip) to write outside the intended directory; run multipart variants through `tools/multipart_mutator.py`.

## Kill rules
- The file is stored but served with a safe content-type / `Content-Disposition: attachment` / `nosniff` and never executes — no code run.
- The upload directory is non-executable and the file is not reachable as a script — storage only.
- Stored SVG/HTML is served as `text/plain` or from a sandboxed/separate origin — no XSS against the target.
- Only a benign file type was accepted and no dangerous variant passed.
- The shell uploaded but you cannot reach or execute it (no URL, random name, blocked) — unproven.
- The upload feature/host is out of scope, or the only effect is quota/DoS on an excluding program.
