# Hunter2 Extreme to V3 Upgrade Roadmap

This is the execution plan for upgrading the existing Hunter2 repository. Work must
follow the levels and phases in order. Do not claim a phase complete until its
acceptance criteria pass.

> Use all methods only against explicitly authorized targets. Public research teaches
> methodology; it is not permission to test the systems mentioned in reports.

## Source Rules

There are two different kinds of online sources:

### Report Sources

These provide concrete public vulnerability cases, conditions, impact, and proof:

- HackerOne public reports and Hacktivity
- Bugcrowd public disclosures where available
- Vendor security advisories and CVE write-ups
- Public researcher write-ups with reproducible technical details
- Public GitHub security advisories and security-lab reports

### Methodology Sources

These provide testing techniques, checklists, payload categories, and defensive
validation guidance:

- OWASP Web Security Testing Guide
- PayloadsAllTheThings
- HackTricks
- HowToHunt
- AllAboutBugBounty
- Az0x7 vulnerability checklist

Every extracted record must preserve the source URL and source type. A methodology
page must not be counted as a disclosed vulnerability report.

## Storage Locations

### Downloaded research, temporary and untracked

```text
D:\bughunting\Axxx_Hunter\.phase1-research\
```

Use this directory for downloaded JSON, HTML, CSV, and temporary source catalogs.
Do not commit raw reports, attachments, screenshots, videos, cookies, credentials, or
target data.

### Extracted Hunter2 knowledge

```text
D:\bughunting\Axxx_Hunter\Hunter2\skills\real-world-playbooks\
```

Store only compact, reusable methodology, source links, safe proof rules, rejection
rules, and routing. Keep extracted knowledge below 400 MB-1 GB.

## Existing Hunter2 Baseline

Hunter2 already contains reconnaissance, scanners, agents, skills, lead tracking,
authenticated workflows, validation, evidence collection, chaining, memory, and
report generation. The upgrade reuses those capabilities.

# Level 1 - Hunter2 Operational Upgrade

Level 1 improves real-world knowledge, routing, evidence, reporting, and coverage in
the existing Hunter2 system.

## Level 1, Phase 1 - Multi-Source Priority Research

### Scope

Collect **70 high-quality public vulnerability cases minimum**, with **14 cases per group**:

1. IDOR / BOLA / BFLA
2. Authentication / Account Takeover
3. SSRF
4. Command Injection / RCE
5. Business Logic / Race Conditions

At least four source families must be represented in the Phase 1 research set. The 70
concrete case records must not come only from HackerOne; external vendor,
research, advisory, and methodology sources must also be downloaded or fetched and
used for cross-checking. Methodology pages are cataloged separately and do not inflate
the 70-case count.

### Required Phase 1 Download Set

Download to `D:\bughunting\Axxx_Hunter\.phase1-research\`:

- HackerOne public JSON/report metadata for selected cases
- Bugcrowd or other public disclosure pages where suitable cases exist
- Vendor/CVE advisory pages for command injection/RCE and SSRF cases
- Public researcher write-ups for business logic and race cases
- OWASP WSTG, PayloadsAllTheThings, HackTricks, HowToHunt,
  AllAboutBugBounty, and Az0x7 checklist references
- PortSwigger Web Security Academy and PortSwigger Research case studies

Only public text/JSON metadata is required. Do not download large attachments or
videos. If a report is unavailable, replace it with another public report in the same
group and record the replacement reason.

### Ten-Minute Audit

Before research, inspect for each group:

- Existing playbook
- Existing agent
- Existing command and scanner
- Existing validation path
- Existing report path

Record gaps in the Phase 1 catalog. This is a focused audit, not the full repository
audit required by Level 2.

### Extraction Format

For every report, extract:

```text
source type and URL
vulnerability group
preconditions
reachable sink or feature
attacker method
safe test approach
proof/evidence
real impact
false-positive or rejection rule
chain opportunities
Hunter2 skill
Hunter2 agent
Hunter2 tool/command
validation handoff
report handoff
```

### Phase 1 Mapping

```text
public report + methodology
  -> structured playbook record
  -> Hunter2 skill
  -> correct agent
  -> existing tool or command
  -> safe validation
  -> evidence record
  -> report template
```

### Phase 1 Outputs

```text
D:\bughunting\Axxx_Hunter\.phase1-research\phase1_reports.jsonl
Hunter2\skills\real-world-playbooks\PHASE1_PRIORITY_LEDGER.md
Hunter2\skills\real-world-playbooks\PHASE1_EXTRACTIONS.md
Hunter2\skills\real-world-playbooks\PHASE1_EXTERNAL_CASES.md
Hunter2\skills\real-world-playbooks\PHASE1_REPORT_CATALOG.md
Hunter2\skills\real-world-playbooks\references\<class>.md
```

### Phase 1 Acceptance Criteria

- 70 cases are actually downloaded or fetched from public sources.
- Exactly 14 usable case records exist for each priority group.
- Every record has a source URL and source type.
- At least four source families are represented.
- Every record has conditions, method, safe proof, impact, and rejection guidance.
- Every group maps to an existing skill, agent, tool, validator, and report path.
- No raw credentials, cookies, target data, or large attachments are stored.
- Focused tests pass and the full test suite has no new failures.

### Estimate

This is a full research pass, not a quick cataloging sprint. Unavailable or
rate-limited pages must be replaced and recorded, not silently counted.

## Level 1, Phase 2 - All-Class Deep Upgrade

### Scope

Apply the Phase 1 extraction format to all remaining web, API, cloud, mobile, Web3,
CI/CD, and LLM classes in the coverage matrix.

### Work

- Add missing or shallow playbooks.
- Use public reports plus methodology sources for each class.
- Map every class to skill, agent, tool, validation, and report output.
- Add coverage states:

```text
TESTED | FOUND | N/A with reason | BLOCKED | PENDING
```

- Add the final coverage matrix to reports.

### Result and Estimate

Hunter2 has consistent knowledge across 30+ classes and cannot silently skip a
reachable class. Estimate: **2-5 working days** for a proper first version.

# Level 2 - V3 Research Architecture

Level 2 starts after Level 1. It adds five architectural phases.

## Level 2, Phase 1 - Structured Target Model

### Add

- Targets and authorized assets
- Hosts, endpoints, parameters, APIs, and technologies
- Users, roles, sessions, and authorization relationships
- Application workflows and state transitions
- Observations, evidence, findings, and test results

### Sources and Inputs

Existing recon output, lead board records, authenticated sessions, scanner output, and
validated reports.

### Result

Hunter2 remembers and links the target architecture across sessions.

### Estimate

**3-5 working days.**

## Level 2, Phase 2 - Attack-Surface and Coverage Graph

### Add

- Relationships between assets, endpoints, parameters, roles, and workflows
- Reachability and authentication requirements
- Coverage status for each attack surface
- Related leads and possible chains

### Result

Hunter2 sees the application as connected attack surfaces instead of isolated scan
targets.

### Estimate

**3-6 working days.**

## Level 2, Phase 3 - Hypothesis Engine

### Add

For each observation, create a hypothesis containing:

- Affected asset and security assumption
- Expected attacker capability
- Priority and confidence
- Required authentication/accounts
- Applicable test methods
- Current status and next action
- Evidence and related findings

```text
observation -> hypothesis -> methods -> test -> evidence -> validated/rejected
```

### Result

Hunter2 reasons about broken security assumptions, workflows, authorization, business
logic, and chains rather than only running signatures.

### Estimate

**4-8 working days.**

## Level 2, Phase 4 - Multi-Agent Test Orchestration

### Add

- Route hypotheses to specialist agents.
- Select multiple safe methods for important hypotheses.
- Run existing scanners against the correct surface.
- Store each result against its hypothesis.
- Link requests, responses, screenshots, and evidence.
- Keep leads, coverage, validation, chaining, and reports synchronized.

### Result

Hunter2 coordinates its existing tools and agents with less manual work.

### Estimate

**4-8 working days.**

## Level 2, Phase 5 - Learning, Metrics, and Harness Parity

### Add

- Record successful and rejected methods.
- Track unresolved hypotheses and recurring gaps.
- Measure coverage, evidence quality, validation rate, and chain quality.
- Promote only verified reusable techniques into playbooks.
- Add next-hunt recommendations.
- Verify equivalent behavior in Claude Code and OpenCode.

### Result

Hunter2 becomes a continuous research loop:

```text
discover -> model -> hypothesize -> test -> correlate -> validate -> chain -> report -> learn
```

### Estimate

**4-8 working days.**

## Total Estimate

| Level | Phase | Work | Estimate |
|---|---|---|---:|
| 1 | 1 | 50 multi-source reports and five-group mapping | 4-8 hours |
| 1 | 2 | All-class playbook and coverage upgrade | 2-5 days |
| 2 | 1 | Structured target model | 3-5 days |
| 2 | 2 | Attack-surface and coverage graph | 3-6 days |
| 2 | 3 | Hypothesis engine | 4-8 days |
| 2 | 4 | Multi-agent orchestration | 4-8 days |
| 2 | 5 | Learning, metrics, and parity | 4-8 days |
| **All** | **All** | **Complete roadmap** | **Approximately 4-8 focused weeks** |

## Final Definition of Done

The roadmap is complete only when the implementation, source catalog, extracted
playbooks, routing, validation, reports, parity checks, and regression tests all pass.
No phase is complete merely because links or documentation were added.
