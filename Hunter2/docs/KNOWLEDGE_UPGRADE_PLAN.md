# Real-Knowledge Upgrade Plan — make Hunter2 test "in real ways"

**Goal:** raise hunting power by importing MORE real disclosed-report knowledge, real
payloads, and real methodology into the **skills / playbooks / scanners** — NOT by
retraining a model. Everything below is public, HTTPS-fetchable **text**, so it adds
~0 to the C: drive (unlike the tool-binary downloads that filled it before).

**Status:** PLAN ONLY — nothing changed yet. Review, then say "build phase 1" etc.

---

## 1. Where the hunter gets "real knowledge" today

| Layer | Source now | Gap |
|---|---|---|
| Per-class playbooks (`skills/real-world-playbooks/references/*.md`, 44 files) | `reddelexc/hackerone-reports` (real reports) + `Az0x7/vulnerability-Checklist` (test flow) | Only 2 sources. Rich in *what to test*, thin on *actual payloads* and cross-source technique. |
| Payloads / wordlists | SecLists, PayloadsAllTheThings — **only linked** in `wordlists/REFERENCES.md`, not baked in | Active scanners fire a handful of built-in payloads, not the real-world corpus. |
| Methodology | `skills/security-arsenal/METHODOLOGY_CHEATSHEET.md` (HowToHunt/HolyTips) | Single file; not per-class. |

Generator that rebuilds the playbooks: `scripts/gen_real_world_playbooks.py`
- `RED_BASE` = reddelexc raw tops-by-bug-type
- `AZ_TREE` / `AZ_BASE` = Az0x7 checklist (mapped via GitHub git-trees API)
- `CLASSES` dict = curated slug → {tier, tool, skill, red-stem, az-files, chains}
- Regenerate: `python scripts/gen_real_world_playbooks.py` then
  `cp -r skills/real-world-playbooks .claude/skills/real-world-playbooks`

---

## 2. New sources to add (all real, all text, all HTTPS)

| # | Source | What it gives | How to fetch |
|---|---|---|---|
| S1 | `swisskyrepo/PayloadsAllTheThings` | The authoritative **payload + bypass library** per class (real SSRF/XXE/SSTI/SQLi/CRLF strings, filter bypasses) | raw `…/<Vuln Folder>/README.md`; map folder→slug via git-trees API (same pattern as `AZ_TREE`) |
| S2 | `KathanP19/HowToHunt` | Step-by-step **real hunting methodology** per class | raw `…/<Class>/README.md` |
| S3 | `daffainfo/AllAboutBugBounty` | Concise real **technique notes + bypasses** per class | raw `…/<Class>.md` |
| S4 | `EdOverflow/bugbounty-cheatsheet` | Quick **technique tables** (redirect/XSS/SSRF params etc.) | raw `cheatsheets/*.md` |
| S5 | `projectdiscovery/nuclei-templates` (community) | More CVE/misconfig **detection templates** (optional; used by `/scan-cves`) | `nuclei -update-templates` (already supported) — templates are small text |

All are on GitHub raw / API — already the exact transport the generator uses. No new deps.

---

## 3. Phase 1 — Enrich all 44 playbooks (safe, text-only)

**Edits to `scripts/gen_real_world_playbooks.py`:**
1. Add `PATT_BASE`, `HTH_TREE/HTH_BASE`, `AAB_BASE`, `EO_BASE` constants for S1–S4.
2. Extend each entry in `CLASSES` with optional keys: `patt` (PayloadsAllTheThings folder), `hth` (HowToHunt path), `aab` (AllAboutBugBounty file), `eo` (cheatsheet file).
3. Add `fetch_patt()`, `fetch_hth()`, `fetch_aab()` mirroring `fetch_az()` (git-trees map + raw fetch, WARN-on-miss so a dead path never breaks the run).
4. In the writer loop, append new sections to each `<slug>.md`:
   - `## Real payloads (PayloadsAllTheThings)` — trimmed code blocks (cap ~40 lines/class to keep files lean)
   - `## Real hunting methodology (HowToHunt / AllAboutBugBounty)` — the ordered steps
   - Keep existing `## How real hackers found it` (reddelexc) + `## Test flow` (Az0x7).
5. Re-mirror to `.claude/skills/` for Claude Code parity.

**Result:** every class file now carries real reports **+ real payloads + real methodology from 5 sources** instead of 2. Pure text; regenerates in one command.

**Verify:** `python scripts/gen_real_world_playbooks.py` prints per-class
`reports=N payloads=Y methodology=Y`; spot-check `references/ssrf.md`, `references/xxe.md`.

---

## 4. Phase 2 — Bake real payloads into the ACTIVE scanners (stronger auto-scan)

Turn style-① scanners from "few built-ins" into "real-world corpus". Add a small
`tools/payloads/` dir of curated `.txt` (derived from PayloadsAllTheThings, committed
as text) and have each scanner load its list with a fallback to the built-ins:

| Scanner | Payload set to inject |
|---|---|
| `tools/xxe_scanner.py` | XXE OOB + file-read + billion-laughs-safe variants |
| `tools/nosqli_scanner.py` | operator-injection + `$where` timing corpus |
| `tools/crlf_scanner.py` | CRLF encodings (`%0d%0a`, `%E5%98%8A`, double-encode) |
| `tools/cors_scanner.py` | origin-bypass regex cases (suffix/prefix/null/scheme) |
| `tools/oob_listener.py` | RCE / cmd-injection templates per OS + Log4Shell strings |
| `tools/multipart_mutator.py` | upload bypass matrix (ext/content-type/magic-byte/polyglot) |

Each scanner already has a payload list — this swaps the hard-coded array for
`load_payloads("<class>", fallback=[...])`. Keeps determinism (files are versioned),
adds real coverage. No network at scan time.

**Safety:** OOB/RCE payloads stay **detection-only** (interactsh callback), no
destructive commands — consistent with the existing safety rails.

---

## 5. Phase 3 — Optional live intel (keep, don't bloat)

- `nuclei -update-templates` on demand (small text, already wired via `/scan-cves`).
- `tools/learn.py` / `/intel` already pull CVE + disclosure intel — extend to cache
  fetched writeups into `memory/` so repeat hunts reuse them (bounded by the existing
  10MB JSONL rotation — no unbounded growth).

---

## 6. What this does and does NOT do

- **DOES:** more real payloads (style ①), more OOB techniques (style ②), more real
  checklists/methodology (style ③) — measurably sharper on every class.
- **DOES NOT:** make logic bugs fully automatic. Business logic / request smuggling /
  cache poisoning still need the agent's reasoning — no repo can download judgment.
- **DOES NOT:** re-bloat C: — all additions are versioned text in the repo (D:).

---

## 7. Effort / order

1. **Phase 1** (playbooks) — highest value/lowest risk. ~1 build pass, then regenerate.
2. **Phase 2** (scanner payloads) — medium; touches 6 scanners + adds `tools/payloads/`.
3. **Phase 3** (live intel cache) — small, optional.

Run order after any build: `python scripts/gen_real_world_playbooks.py` →
`cp -r skills/real-world-playbooks .claude/skills/real-world-playbooks` →
`python -m pytest -q` (scanners have unit tests) → `python tools/preflight.py`.
