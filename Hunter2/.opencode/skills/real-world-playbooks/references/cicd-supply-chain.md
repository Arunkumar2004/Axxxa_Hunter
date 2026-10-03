# Real-World Playbook - CI/CD and Supply Chain

**Class:** `cicd-supply-chain` · **Coverage-matrix tier:** 2 (supply chain A08) / 3 (CI/CD injection) · **Hunter2:** `sast_scan.py` · `cicd_scanner.sh` · `/sast` (guided-manual) · **Skill:** cicd-security

**Route:** `cicd-security` -> `cloud-hunter`/`novel-vuln-reasoner` -> `cicd_scanner.sh`,
`sast_scan.py`, source review -> isolated test workflow proof -> validator/report-writer.

## Conditions

- Workflow, runner, package registry, build hook, artifact, or deployment path is in scope.

## Safe method

- Review trigger trust, fork/PR permissions, expression injection, secret exposure,
  runner labels, dependency resolution, and artifact provenance.
- Use a disposable branch/package and a canary value in an isolated workflow.
- Confirm package namespace precedence without publishing a malicious package.

## Proof and rejection

- Confirm only when a controlled workflow executes the canary with unauthorized
  privileges or exposes a scoped test secret.
- Reject a package-name collision without resolver/build execution evidence.
- Never exfiltrate real secrets or poison a production registry/runner.

## Test flow / checklist — do these in order
*(public methodology — SLSA / OpenSSF Scorecard / GitHub Advisory DB / PayloadsAllTheThings CI-CD; run each, mark result in the coverage matrix)*

[ ] Inventory pipeline config: `.github/workflows/`, GitLab CI, Jenkinsfile, CircleCI, build hooks, Dockerfiles
[ ] Check triggers that run with a write token/secrets on untrusted input: `pull_request_target`, `workflow_run`, `issue_comment`
[ ] Hunt expression injection: untrusted `${{ github.event.* }}` (PR title/branch/body) flowing into a `run:` shell step
[ ] Check secret exposure: secrets echoed to logs, passed to fork-triggered jobs, or readable by actions pinned to mutable tags
[ ] Review pinning: actions/dependencies referenced by branch or tag instead of a pinned SHA; unpinned third-party actions
[ ] Enumerate internal package names from lockfiles/manifests; test dependency-confusion namespace precedence on the public registry
[ ] Check self-hosted runner labels/isolation: are public-repo PRs scheduled onto privileged/self-hosted runners?
[ ] Review artifact provenance/integrity: unsigned artifacts, no SLSA attestation, tampering between build and deploy
[ ] Check build-hook / deploy-path trust: who can trigger deploys, and can a low-priv contributor reach prod?
[ ] Prove impact only in a disposable branch/package with a canary value in an isolated workflow — never touch a prod registry/runner

## What gets this rejected (kill before you write)
*(from `skills/triage-validation/SKILL.md` — one wrong answer = kill it and move on)*

- Dependency-name collision or "package name is free on the public registry" without resolver/build-execution evidence.
- Unpinned action or missing SLSA provenance reported as-is with no exploit path.
- Secrets that are test/canary-only, expired, or already public.
- Config observations on a public repo with no way for an external attacker to trigger the vulnerable job.
- Anything that requires actually publishing a malicious package, poisoning a real registry, or exfiltrating real secrets — do not do it; report the precedence condition instead.
- Findings on a repo/pipeline outside the program's defined scope.
- **Conditionally valid (only WITH a chain):** expression injection / poisoned pipeline → secret exfil or runner code execution proven with a scoped canary; dependency confusion → your test package actually resolves/executes in a controlled build.

## Sources

SLSA, OpenSSF Scorecard, GitHub Advisory Database, CISA KEV, and Hunter2's
`cicd-security` skill.
