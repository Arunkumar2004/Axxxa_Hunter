---
description: Run the hunt loop across many hosts concurrently with a bounded job pool; every host is scope-checked first and out-of-scope hosts are skipped. Usage: /parallel-hunt hosts.txt [--jobs 8] [--scope scope.txt] [--cmd "..."]
---

# /parallel-hunt

Hunt a whole list of hosts at once instead of one at a time. Bounded concurrency,
per-host output dirs, and a mandatory scope gate.

## Usage

```bash
tools/parallel_hunt.sh hosts.txt
tools/parallel_hunt.sh hosts.txt --jobs 8 --scope scope.txt
tools/parallel_hunt.sh hosts.txt --cmd "tools/cors_scanner.py {host} --json"
```

- `--jobs N` concurrency (default 4).
- `--scope FILE` domain patterns (one per line, `*.target.com` allowed); each host
  is checked with `scope_checker.py` and skipped if out of scope.
- `--cmd TMPL` per-host command; `{host}` and `{outdir}` are substituted. Default
  runs `vuln_scanner.sh` against each host recon dir.

Results land in `findings/<host>/` with a `parallel_hunt.log` per host.

## Safety

The scope gate runs before any request. Out-of-scope hosts are logged and never
touched. Combine with the toolkit rate limits for large lists.
