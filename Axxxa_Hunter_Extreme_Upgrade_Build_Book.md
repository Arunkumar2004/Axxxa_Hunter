# Axxxa_Hunter Extreme Upgrade — Master Build Book

## Version
**Build Book v1.0**

## Purpose

Upgrade the existing **Axxxa_Hunter** repository into an advanced, evidence-driven, agentic security research and bug-hunting platform.

Repository:
`https://github.com/Arunkumar2004/Axxxa_Hunter`

This document is intended to be given to an AI coding agent as the primary technical build specification.

The AI must work from the existing repository rather than replacing it blindly.

---

# 1. Core Objective

The target system is not:

```text
Target
→ run scanners
→ print findings
```

The target system is:

```text
Authorized Target
→ Scope Enforcement
→ Reconnaissance
→ Attack-Surface Graph
→ Technology / Architecture Understanding
→ Authentication & Authorization Mapping
→ Vulnerability Hypothesis Generation
→ Applicable Method Selection
→ Multi-Method Testing
→ SAST + DAST + Browser + API Correlation
→ Evidence Collection
→ Validation
→ False-Positive Elimination
→ Impact Analysis
→ Attack-Chain Analysis
→ Professional Report
→ Controlled Knowledge Update
```

The system must maximize:

- attack-surface coverage
- testing depth
- evidence quality
- validation accuracy
- reproducibility
- useful impact analysis

Do **not** optimize merely for the number of reported vulnerabilities.

---

# 2. Non-Negotiable Build Rules

## Rule 1 — Inspect Before Modifying

Before writing code:

1. inspect the entire repository
2. understand startup flow
3. understand agent flow
4. identify all skills
5. identify all tools
6. identify all vulnerability modules
7. identify configuration
8. identify memory/state
9. identify reporting
10. identify authentication support
11. identify external tool integrations
12. identify existing tests

Do not assume README content equals implementation.

## Rule 2 — Preserve Existing Capabilities

Existing working scanners, agents, skills, integrations and workflows must be preserved unless there is a demonstrated reason to replace them.

Upgrade:

```text
Existing Capability
+
New Coverage
+
New Validation
+
New Evidence
```

Do not remove a mature tool simply because a new implementation is being created.

## Rule 3 — Do Not Treat Scanner Output as Proof

Every finding follows:

```text
Discovery
→ Candidate
→ Validation
→ Confirmed
```

or:

```text
Candidate
→ False Positive / Rejected
```

## Rule 4 — Do Not Claim Untested Coverage

The system must distinguish:

- TESTED
- NOT TESTED
- NOT APPLICABLE
- BLOCKED
- REQUIRES AUTHENTICATION
- REQUIRES SOURCE
- REQUIRES BROWSER
- REQUIRES MANUAL VALIDATION
- CANDIDATE
- VALIDATED
- FALSE POSITIVE

## Rule 5 — Authorized Scope Only

Implement strict:

- scope enforcement
- out-of-scope blocking
- rate limits
- request budgets
- concurrency controls
- destructive-action protection
- credential protection
- secret redaction
- audit logs

Use the system only against explicitly authorized targets.

---

# 3. Phase 0 — Repository Forensics

Create:

`docs/current-architecture.md`

Document the actual existing architecture.

Include:

```text
User
→ entry point
→ commander/orchestrator
→ agents
→ skills
→ tools
→ recon
→ vulnerability testing
→ validation
→ reporting
```

For every component record:

| Component | Current Role | Files | Dependencies | Inputs | Outputs | Status |
|---|---|---|---|---|---|---|

Also create:

`docs/current-vulnerability-matrix.md`

---

# 4. Current Vulnerability Matrix

For EVERY vulnerability currently supported by Axxxa, document:

- agent
- skill
- script
- tool
- attack surface
- input locations
- current technique
- payload strategy
- passive/active
- authentication support
- browser support
- API support
- SAST support
- OOB support
- validation
- evidence
- false-positive handling
- reporting
- limitations

Example:

```text
SQL Injection

Existing tools:
- existing SQLi integrations discovered in repository

Current surfaces:
- list actual surfaces from code

Current techniques:
- list actual techniques from code

Current validation:
- list actual validation

Missing:
- list evidence-backed gaps
```

Do this for all current vulnerability classes.

---

# 5. Security Knowledge Engine

Build a new controlled knowledge layer.

## Goal

Axxxa must be able to use security knowledge from:

- OWASP methodologies
- OWASP WSTG
- PortSwigger Web Security Academy
- CVE/NVD data
- vendor security advisories
- public security research
- public vulnerability disclosures
- security-tool documentation
- public GitHub security research/code
- other legally usable authoritative/public sources

Respect source licensing, usage restrictions, attribution and robots/access policies.

Do not blindly copy entire reports into prompts.

---

# 6. Knowledge Pipeline

Implement:

```text
Source
→ Fetch
→ Parse
→ Normalize
→ Deduplicate
→ Classify
→ Extract Security Pattern
→ Store Provenance
→ Confidence
→ Human/AI Review
→ Lab Validation
→ Knowledge Entry
```

Each knowledge item should contain:

```yaml
id:
source:
source_type:
title:
published_at:
updated_at:
vulnerability_class:
attack_surface:
input_location:
application_context:
technique:
detection_signal:
validation_method:
impact:
technology:
prerequisites:
limitations:
confidence:
provenance:
license_notes:
last_verified:
```

---

# 7. Real-World Case Knowledge

Public vulnerability reports should be converted into patterns.

Do NOT train the system to copy reports.

Extract:

```text
Application Context
→ Attack Surface
→ Researcher's Observation
→ Hypothesis
→ Testing Method
→ Evidence
→ Validation
→ Impact
→ Root Cause
```

Example:

```text
IDOR

Surface:
REST API

Object:
Invoice

Research Pattern:
Compare object authorization across identities

Evidence:
Unauthorized object returned

Validation:
Second authorized identity

Impact:
Cross-user data access
```

The knowledge engine should teach Axxxa:

**how researchers reasoned**, not simply what payload they used.

---

# 8. Security Research Lab

Build an isolated local security-testing environment.

Purpose:

```text
Knowledge
→ Hypothesis
→ Safe Lab
→ Execute Test
→ Observe
→ Compare
→ Validate Detection
→ Update Detector
```

Use intentionally vulnerable applications and security training labs.

The lab must never be connected to production targets.

Store:

- lab target
- vulnerability
- expected result
- actual result
- detector result
- false positive result
- regression status

---

# 9. Knowledge Retrieval

When Axxxa encounters a target:

```text
Target Observation
→ Relevant Knowledge Retrieval
→ Attack-Surface Matching
→ Vulnerability Hypotheses
→ Method Selection
```

Knowledge retrieval should be contextual.

Do not retrieve the entire knowledge base.

Example:

```text
GraphQL endpoint discovered
+
authenticated API
+
object IDs
```

Retrieve knowledge related to:

- GraphQL authorization
- BOLA/IDOR
- nested object access
- batching
- mutation authorization

---

# 10. Attack-Surface Graph

Create a central graph.

Entities:

```text
Domain
Subdomain
IP
Port
Service
Technology
Endpoint
Parameter
Request
Response
Cookie
Header
API
GraphQL operation
WebSocket
File
Authentication State
User
Role
Tenant
Object
Workflow
Vulnerability Candidate
Finding
Evidence
```

Relationships:

```text
domain → subdomain
subdomain → service
service → endpoint
endpoint → parameter
endpoint → authentication state
endpoint → technology
endpoint → object
object → authorization
finding → evidence
finding → attack chain
```

This graph becomes the central state of the Hunter.

---

# 11. Reconnaissance Upgrade

Recon must produce structured data, not just a list of URLs.

Collect where applicable:

- domains
- subdomains
- DNS
- IPs
- ports
- HTTP services
- technologies
- JavaScript
- source maps
- APIs
- GraphQL
- WebSockets
- forms
- parameters
- files
- redirects
- authentication
- OAuth
- cloud assets
- exposed services

Normalize and deduplicate all results.

---

# 12. Authentication State Graph

Model:

```text
Unauthenticated
→ Registration
→ Verification
→ Login
→ MFA
→ Authenticated
→ Role Change
→ Password Change
→ Email Change
→ Recovery
→ Logout
```

Where authorized credentials exist, maintain separate contexts:

```text
User A
User B
Manager
Admin
Tenant A
Tenant B
```

Never expose credentials in reports.

---

# 13. Authorization Graph

Model:

```text
Identity
→ Role
→ Tenant
→ Object
→ Permission
→ Action
```

Use this for:

- IDOR
- BOLA
- privilege escalation
- GraphQL authorization
- WebSocket authorization
- business logic

---

# 14. Data-Flow Graph

When source is available:

```text
Input
→ Transformation
→ Sanitization
→ Storage
→ Sink
```

Use for:

- SQLi
- XSS
- command injection
- SSTI
- SSRF
- prototype pollution
- deserialization
- path/file-related issues

---

# 15. Workflow Graph

Represent:

```text
State A
→ Action
→ State B
→ Action
→ State C
```

Use for:

- business logic
- authentication
- account recovery
- payment-like workflows
- quotas
- coupon logic
- inventory
- approval flows
- race conditions

---

# 16. Universal Vulnerability Model

Every vulnerability module must implement:

```text
Vulnerability
→ Applicable Surfaces
→ Applicable Inputs
→ Context
→ Hypothesis
→ Methods
→ Detection Signals
→ Validation
→ Impact
→ Evidence
→ Report
```

Create a common interface.

Example conceptual interface:

```python
class VulnerabilityModule:
    name
    applicable_surfaces()
    prerequisites()
    generate_hypotheses()
    select_methods()
    run_tests()
    collect_evidence()
    validate()
    assess_impact()
    generate_finding()
```

Adapt to the existing architecture instead of forcing this exact class if the repository uses another design.

---

# 17. SQL Injection Engine

Preserve existing SQLi integrations.

Expand applicable coverage:

### Surfaces

- query parameters
- path parameters
- form fields
- JSON
- XML
- multipart
- cookies
- headers
- GraphQL
- WebSockets
- search
- filters
- sorting
- pagination
- import/workflow paths

### Contexts

Where applicable:

- string
- numeric
- LIKE
- WHERE
- ORDER BY
- GROUP BY
- IN
- dynamic query
- stored procedure
- ORM/raw SQL boundary

### Techniques

Where applicable:

- error-based
- differential/boolean
- time-based
- blind
- union-style detection
- OOB
- second-order
- source-to-sink analysis

### Source analysis

Detect:

```text
input
→ data flow
→ query construction
→ database sink
```

Do not report solely from suspicious source patterns.

Require corroborating evidence where possible.

---

# 18. XSS Engine

Support applicable:

- reflected
- stored
- DOM

Surfaces:

- URL
- form
- JSON
- XML
- headers
- cookies
- GraphQL
- WebSocket
- stored content
- admin views

Contexts:

- HTML
- attribute
- JavaScript
- CSS
- URL
- SVG
- DOM

Add browser validation.

Add source-to-sink analysis.

Consider:

- postMessage
- client routing
- framework sinks
- WebSocket → DOM
- stored → privileged view

---

# 19. IDOR / BOLA Engine

Never define IDOR as "ID changed successfully."

Build identity comparison:

```text
A → A object
A → B object
B → A object
```

Test applicable:

- read
- create
- update
- delete
- download
- export
- bulk
- nested objects
- REST
- GraphQL
- WebSockets
- cross-tenant

Require actual unauthorized access or modification evidence.

---

# 20. SSRF Engine

Discover server-side URL fetching.

Test applicable:

- URL parameters
- JSON
- XML
- webhooks
- previews
- importers
- image fetchers
- document processors
- PDF generators
- integrations
- background workers

Model:

```text
input
→ parser
→ validation
→ DNS
→ redirect
→ HTTP client
→ destination
```

Support safe validation for internal/cloud/blind behavior where authorized.

---

# 21. Authentication Engine

Use state-machine analysis.

Test applicable:

- authentication bypass
- session handling
- recovery
- password reset
- account changes
- MFA flow
- session fixation
- session invalidation
- verification-state bypass

---

# 22. JWT Engine

Analyze:

- signature validation
- algorithm handling
- key handling
- issuer
- audience
- expiry
- claims
- refresh tokens
- authorization impact

Do not report token anomalies without security relevance.

---

# 23. OAuth Engine

Model:

```text
Client
→ Authorization Server
→ Redirect
→ Code
→ Token
→ Identity
→ Session
```

Test applicable:

- redirect handling
- state
- nonce
- PKCE
- code binding
- client identity
- token handling
- account identity binding

---

# 24. CSRF Engine

Discover state-changing operations.

Consider:

- tokens
- token binding
- Origin
- Referer
- SameSite
- JSON
- multipart
- REST
- GraphQL

Prioritize sensitive actions.

---

# 25. CORS Engine

Do not report permissive CORS alone.

Model:

```text
Attacker Origin
+
Credentials
+
Sensitive Endpoint
+
Readable Response
```

Require meaningful impact evidence where possible.

---

# 26. XXE Engine

Discover XML processing.

Consider:

- XML APIs
- SOAP
- SVG
- SAML
- uploads
- document processing

Support appropriate safe error/blind/OOB validation.

---

# 27. SSTI Engine

Model:

```text
Input
→ Template
→ Template Engine
→ Expression Evaluation
→ Capability
```

Distinguish reflection from template execution.

---

# 28. Command Injection Engine

Discover process-execution paths.

Consider:

- command execution
- subprocess
- conversion utilities
- image processing
- PDF processing
- CI/CD
- background jobs

Use source-to-sink analysis when source exists.

Use safe validation.

---

# 29. Deserialization Engine

Identify:

- serialization format
- parser
- object creation
- dangerous sinks
- applicable gadget paths

Support applicable Java, PHP, .NET and Python ecosystems.

Use safe validation.

---

# 30. Race Engine

Create reusable concurrency infrastructure.

Model:

```text
State Before
→ Concurrent Requests
→ State After
```

Test applicable security/business operations.

Detect invariant violations.

---

# 31. Business Logic Engine

Build workflow/state-machine reasoning.

Discover:

```text
state
→ action
→ state
```

Infer invariants.

Examples:

- ownership
- authorization
- pricing
- quantity
- quota
- verification
- workflow order
- transaction state

Test unusual but valid request sequences.

Require evidence of actual impact.

---

# 32. GraphQL Engine

Build:

```text
Schema
→ Query
→ Mutation
→ Field
→ Argument
→ Object
```

Test applicable:

- introspection
- field authorization
- object authorization
- mutation authorization
- nested access
- aliases
- batching
- depth
- complexity
- subscriptions

Correlate with authorization engine.

---

# 33. WebSocket Engine

Model:

```text
Connect
→ Authenticate
→ Subscribe
→ Read
→ Write
```

Test applicable:

- authentication
- authorization
- Origin
- cross-user access
- subscription authorization
- message authorization

---

# 34. HTTP Request Smuggling Engine

Where infrastructure visibility allows:

```text
Client
→ CDN
→ WAF
→ Proxy
→ Load Balancer
→ Application
```

Analyze parser differences and request-boundary behavior.

Avoid disruptive testing.

---

# 35. Cache Poisoning / Cache Deception

Model:

```text
Request
→ Cache Key
→ Unkeyed Input
→ Response
→ Cache
→ Subsequent Request
```

Require evidence of security-relevant cached behavior.

---

# 36. HTTP Parameter Pollution

Analyze parser differences across:

```text
Client
→ Proxy
→ Framework
→ Application
```

Detect inconsistent parameter interpretation.

---

# 37. CRLF / Response Splitting

Consider:

- headers
- redirects
- host-related headers
- proxy-related headers

Validate actual response behavior and impact.

---

# 38. Prototype Pollution

Model:

```text
Source
→ Object Merge
→ Prototype Mutation
→ Gadget
→ Security Impact
```

Distinguish pollution from exploitable impact.

---

# 39. Open Redirect

Discover:

- redirect
- next
- return
- continue
- destination
- target
- callback

Consider interaction with authentication/OAuth flows.

---

# 40. Secrets Engine

Search applicable:

- source
- JavaScript
- source maps
- Git history
- configuration
- CI/CD
- containers
- logs
- public files
- API responses

Classify:

```text
secret
→ valid?
→ scope?
→ privilege?
→ environment?
```

Do not report arbitrary strings as secrets.

---

# 41. Cloud / Kubernetes / Infrastructure

Build relationship mapping:

```text
DNS
→ Cloud Asset
→ Storage
→ IAM
→ Compute
→ Container
→ Kubernetes
→ CI/CD
→ Internal Service
```

Correlate infrastructure findings with application findings.

---

# 42. Subdomain Takeover

Model:

```text
DNS
→ CNAME
→ Provider
→ Resource
→ Claimability
→ HTTP Evidence
```

Require strong evidence.

---

# 43. AI / LLM Security Engine

Model AI systems as:

```text
User
→ LLM
→ System Instructions
→ Memory
→ RAG
→ Tools
→ Database
→ External API
→ Action
```

Consider applicable:

- prompt injection
- indirect prompt injection
- system prompt exposure
- sensitive data leakage
- excessive agency
- tool misuse
- RAG poisoning
- multimodal injection
- output-to-dangerous-sink paths
- authorization failures around AI actions

Focus on trust boundaries and real impact.

---

# 44. Web3 Engine

Preserve existing Web3 integrations.

Use appropriate combinations of:

- static analysis
- symbolic analysis
- fuzzing
- invariant testing
- reasoning

Do not remove existing mature tooling.

---

# 45. Multi-Method Orchestrator

Create a shared decision layer.

Input:

```text
Attack Surface
Technology
Authentication State
Source Availability
Observed Behavior
Knowledge
```

Output:

```text
Applicable Vulnerabilities
+
Applicable Methods
+
Tool Selection
+
Validation Plan
```

Example:

```text
GraphQL discovered
→ GraphQL methods

XML discovered
→ XML/XXE methods

File upload discovered
→ upload-related analysis

Source available
→ SAST/data-flow methods

JavaScript-heavy target
→ browser/DOM methods

Two authorized users
→ authorization comparison
```

Do not run every tool everywhere.

---

# 46. Tool Orchestration

For every integrated tool maintain:

```text
Tool
Purpose
Input
Output
Supported Vulnerabilities
Strengths
Limitations
Authentication
Browser requirement
Network requirement
Validation role
```

Create adapters where needed.

Normalize tool output into a common internal format.

---

# 47. Evidence Engine

Every test should produce structured evidence.

Store:

```yaml
test_id:
finding_id:
timestamp:
target:
scope:
endpoint:
method:
parameter:
authentication_state:
technique:
tool:
request_reference:
response_reference:
browser_reference:
source_reference:
observation:
validation_status:
```

Redact credentials, tokens and sensitive secrets.

---

# 48. Finding Lifecycle

Use:

```text
DISCOVERED
→ CANDIDATE
→ NEEDS_VALIDATION
→ VALIDATED
→ IMPACT_VERIFIED
```

or:

```text
CANDIDATE
→ FALSE_POSITIVE
```

Maintain reason codes.

---

# 49. Finding Correlation

Merge duplicate results.

Example:

```text
SQLMap
+
Ghauri
+
SAST
+
DAST
```

may represent one SQLi finding.

Create:

```text
Finding
→ Evidence 1
→ Evidence 2
→ Evidence 3
```

instead of three duplicate findings.

---

# 50. Attack Chain Engine

Represent:

```text
Finding A
→ enables
Finding B
→ enables
Impact
```

Only create evidence-supported chains.

Do not convert hypothetical chains into confirmed findings.

---

# 51. Professional Report Engine

Generate reports with:

## Executive Summary

- scope
- target
- testing period
- assets
- candidates
- validated findings

## Attack Surface

- domains
- endpoints
- APIs
- technologies
- authentication states
- infrastructure

## Findings

Each finding:

```text
Title
Vulnerability Class
Severity
Confidence
Affected Asset
Endpoint
Parameter
Authentication State

What Was Tested
Methods Attempted
Successful Method

Evidence
Validation
Impact
Attack Chain

Reproduction
Root Cause
Remediation
```

## Coverage

Show exactly what was:

- tested
- not tested
- not applicable
- blocked
- authentication-required
- source-required
- browser-required
- manually required

---

# 52. Report Quality Rules

Never write:

> "No vulnerabilities found"

when only partial testing occurred.

Instead report:

> "No validated findings were identified within the tested attack surfaces and methods."

Reports must be reproducible and evidence-driven.

---

# 53. Dashboard

Create a structured security dashboard showing:

```text
Target
Scope
Recon Progress
Attack Surface
Authentication States
Testing Progress
Candidates
Validated Findings
False Positives
Coverage Gaps
Attack Chains
Knowledge Used
```

If the existing project is CLI-only, implement the core data model/API first and only add UI where consistent with the repository architecture.

---

# 54. Continuous Knowledge Update

Build a controlled updater:

```text
Public/Authorized Source
→ Fetch
→ Normalize
→ Deduplicate
→ Extract
→ Classify
→ Compare Existing Knowledge
→ Candidate Technique
→ Isolated Lab Test
→ Review
→ Knowledge Update
```

Do not automatically modify production detection logic solely because a new internet article was discovered.

New techniques must be evaluated before becoming active detection logic.

---

# 55. Knowledge Provenance

Every knowledge item must retain:

- source
- URL/reference
- source type
- date
- extracted technique
- confidence
- last verification
- licensing/usage note

Do not remove provenance.

---

# 56. Learning From Axxxa's Own Results

After each authorized hunt:

```text
Test
→ Observation
→ Validation
→ Finding
→ False Positive
→ Lesson
```

Store lessons as structured knowledge.

Examples:

```text
Technique produced false positive on framework X

Technique succeeded against API pattern Y

Browser validation required for pattern Z
```

Do not automatically rewrite core detection logic based on one observation.

---

# 57. Regression Knowledge

Every validated detector should have regression tests.

When a detector changes:

```text
Old Test Cases
+
New Test Cases
+
False Positive Cases
```

must be executed.

---

# 58. Database / Storage

Create a persistent model for:

```text
targets
scopes
assets
endpoints
parameters
technologies
identities
sessions
workflows
tests
tools
observations
evidence
findings
knowledge
sources
attack_chains
regressions
audit_events
```

Use the existing project's database/storage architecture where possible.

Do not introduce a database unnecessarily if the project already has a suitable persistence layer.

---

# 59. API / Internal Interfaces

Create clean internal interfaces for:

```text
Recon
Attack Surface
Knowledge
Testing
Validation
Evidence
Findings
Chains
Reports
```

Every module should communicate through structured data.

Avoid fragile parsing of human-readable CLI output where structured output exists.

---

# 60. Agent Architecture

Recommended conceptual agents:

```text
Scope Guardian
Recon Commander
Attack Surface Analyst
Technology Analyst
Authentication Analyst
Authorization Analyst
Vulnerability Researcher
SAST Analyst
DAST Analyst
Browser Analyst
API Analyst
Business Logic Analyst
Validation Officer
Impact Analyst
Chain Analyst
Knowledge Researcher
Report Writer
```

Do not create agents unnecessarily if the existing architecture can support the responsibility through skills/modules.

The key is clear responsibility.

---

# 61. Agent Decision Flow

```text
Scope Guardian
→ Recon Commander
→ Attack Surface Analyst
→ Technology Analyst
→ Authentication/Authorization Analysis
→ Knowledge Retrieval
→ Vulnerability Researcher
→ Method Selection
→ Testing Agents
→ Validation Officer
→ Impact Analyst
→ Chain Analyst
→ Report Writer
```

---

# 62. Avoid Agent Hallucination

Agents must not claim:

- a test was performed when it was not
- evidence exists when it does not
- source code was analyzed when unavailable
- authentication was bypassed without proof
- a vulnerability is confirmed without validation

Every important claim should reference evidence.

---

# 63. Scheduling / Long-Running Mode

If continuous operation is supported, implement:

- job queue
- retry handling
- request budgets
- pause/resume
- state persistence
- checkpointing
- crash recovery
- scope revalidation

A long-running process must not continuously repeat identical tests.

---

# 64. Performance

Use:

- deduplication
- caching
- request budgets
- adaptive scheduling
- parallelism where safe
- tool prioritization
- evidence reuse

Do not trade correctness for speed.

---

# 65. Security of Axxxa Itself

Protect:

- credentials
- API keys
- tokens
- reports
- target information
- knowledge database
- tool execution
- command execution
- browser sessions

Implement least privilege.

Audit sensitive operations.

---

# 66. Testing Strategy

Create tests at multiple levels.

## Unit

Test:

- parsers
- graph operations
- knowledge extraction
- coverage logic
- finding correlation
- evidence handling
- scope logic

## Integration

Test:

- recon → graph
- graph → vulnerability selection
- scanner → normalized result
- candidate → validation
- evidence → report

## End-to-End

Use isolated vulnerable applications.

Test:

```text
Target
→ Recon
→ Detection
→ Validation
→ Report
```

## Regression

Every fixed false positive becomes a regression test where practical.

---

# 67. Vulnerability Test Lab Matrix

Create controlled lab cases for each supported vulnerability.

Minimum structure:

```text
Vulnerability
Lab Target
Expected Detection
Expected Evidence
Expected Validation
Expected Report
False Positive Cases
```

Do not use real third-party systems as test targets.

---

# 68. Coverage Matrix

Create:

`docs/vulnerability-coverage.md`

Columns:

```text
Vulnerability
Attack Surface
Technique
Tool
Authentication
SAST
DAST
Browser
API
OOB
Validation
Evidence
Status
Limitations
```

This becomes the authoritative coverage document.

---

# 69. Definition of Done

A vulnerability module is mature only when it can answer:

```text
What attack surface was tested?

What input locations were tested?

What techniques were attempted?

Which tools were used?

What evidence was obtained?

How was it validated?

What is the actual impact?

What was not tested?

What prerequisites were missing?

Can it form an evidence-supported chain?
```

---

# 70. Implementation Order

Build in waves.

## WAVE 1 — Forensics

- repository audit
- current architecture
- current vulnerability matrix
- tool matrix
- existing tests

Do not modify core functionality.

## WAVE 2 — Shared Infrastructure

- normalized data model
- attack-surface graph
- evidence model
- finding lifecycle
- coverage tracking
- scope enforcement

## WAVE 3 — Knowledge

- source connectors
- parser
- normalization
- knowledge database
- retrieval
- provenance
- research-case extraction

## WAVE 4 — Vulnerability Engines

Upgrade each existing vulnerability module.

Prioritize shared infrastructure first.

## WAVE 5 — Correlation

- SAST + DAST
- browser + API
- authentication + authorization
- duplicate finding correlation
- attack chains

## WAVE 6 — Validation

- evidence engine
- independent confirmation
- false-positive controls
- impact validation

## WAVE 7 — Reporting

- professional reports
- coverage reports
- evidence references
- attack-chain visualization

## WAVE 8 — Research Lab

- isolated vulnerable targets
- detector regression
- technique verification

## WAVE 9 — Continuous Knowledge

- controlled source updates
- new research detection
- candidate technique generation
- lab validation
- approved knowledge updates

## WAVE 10 — Optimization

- performance
- scheduling
- caching
- reliability
- observability

---

# 71. Required Files / Documentation

Create or update appropriate files based on the existing repository.

At minimum, documentation should include:

```text
docs/
├── current-architecture.md
├── upgraded-architecture.md
├── current-vulnerability-matrix.md
├── vulnerability-coverage.md
├── tool-matrix.md
├── knowledge-engine.md
├── attack-surface-graph.md
├── validation-engine.md
├── evidence-model.md
├── attack-chain-engine.md
├── reporting.md
├── security-model.md
├── testing.md
└── development-guide.md
```

Do not create duplicate documentation if equivalent files already exist; update the existing canonical documents.

---

# 72. Final Architecture

The completed system should conceptually look like:

```text
                         AXXXA HUNTER
                              │
                     ┌────────┴────────┐
                     │                 │
                TARGET ENGINE    KNOWLEDGE ENGINE
                     │                 │
                  Scope             OWASP
                     │             Research
                  Recon           Disclosures
                     │             CVEs
                     │             Advisories
                     │             Tool Docs
                     │                 │
                     └────────┬────────┘
                              ↓
                     ATTACK-SURFACE GRAPH
                              ↓
                     APPLICATION MODEL
                              ↓
                 AUTH / AUTHORIZATION GRAPH
                              ↓
                      HYPOTHESIS ENGINE
                              ↓
                      METHOD SELECTOR
                              ↓
            ┌─────────────────┼─────────────────┐
            ↓                 ↓                 ↓
          SAST              DAST             Browser
            ↓                 ↓                 ↓
            └─────────────────┼─────────────────┘
                              ↓
                         API Analysis
                              ↓
                         Validation
                              ↓
                          Evidence
                              ↓
                       Impact Analysis
                              ↓
                       Chain Analysis
                              ↓
                           REPORT
                              ↓
                    CONTROLLED KNOWLEDGE
                           UPDATE
```

---

# 73. Final Product Behavior

When a user gives an authorized target:

```text
1. Verify scope
2. Discover attack surface
3. Build graph
4. Identify technologies
5. Identify authentication states
6. Identify authorization relationships
7. Retrieve relevant security knowledge
8. Generate vulnerability hypotheses
9. Select applicable methods
10. Run appropriate tools
11. Perform deeper analysis
12. Correlate results
13. Validate candidates
14. Eliminate false positives
15. Assess impact
16. Search for supported chains
17. Record evidence
18. Generate report
19. Record coverage gaps
20. Store validated research lessons
```

---

# 74. Final Quality Standard

The upgraded Axxxa must behave less like:

```text
Scanner Collection
```

and more like:

```text
Agentic Security Research Platform
```

The defining characteristics are:

### Broad

Understands many attack surfaces and vulnerability classes.

### Deep

Uses multiple applicable testing techniques rather than one payload.

### Context-aware

Understands technology, workflow, authentication and authorization.

### Evidence-driven

Does not claim vulnerabilities without evidence.

### Validation-first

Separates candidates from confirmed findings.

### Research-aware

Learns structured patterns from authoritative methodologies and public security research.

### Adaptive

Chooses methods based on the discovered target rather than blindly running everything.

### Chain-aware

Understands relationships between validated findings.

### Transparent

Reports exactly what was and was not tested.

### Controlled

Operates only within authorized scope.

---

# 75. Final Developer Instruction

You are responsible for implementing this build book against the actual Axxxa_Hunter repository.

Do not pretend functionality exists before implementing and testing it.

Do not fabricate test results.

Do not claim complete vulnerability coverage.

At each wave:

1. inspect
2. design
3. implement
4. test
5. document
6. report remaining gaps

Before major architectural changes, explain the existing implementation and the proposed change.

Preserve working functionality.

Prefer mature existing security tools where appropriate.

Build reusable security infrastructure rather than duplicating logic across vulnerability modules.

The final result must provide not just:

**"Bug found."**

It must provide:

**"What was tested → how it was tested → why it was considered a candidate → what evidence was collected → how it was validated → what impact was demonstrated → what remains untested."**

That is the required standard for the upgraded Axxxa_Hunter.
