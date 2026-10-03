# Axxxa_Hunter V3 — Autonomous Web Security Research Engine
## Extreme Coverage & Evidence-Driven Bug Hunting Build Book

**Version:** 3.0  
**Status:** Engineering Blueprint  
**Purpose:** Upgrade Axxxa_Hunter from a scanner/agent collection into a continuously reasoning, evidence-driven web security research platform.

> **Core principle:** Maximum practical coverage, not a claim of finding every possible bug.  
> Axxxa must operate only against targets and accounts explicitly authorized for testing.

---

# 1. V3 Mission

Axxxa_Hunter V3 is designed to answer five questions continuously:

1. **What exists?**
2. **How does the application work?**
3. **What security assumptions exist?**
4. **Which assumptions might be broken?**
5. **Can each suspected weakness be proven with evidence?**

The target operating model is:

```text
AUTHORIZED TARGET
      ↓
SCOPE ENFORCEMENT
      ↓
DISCOVERY
      ↓
APPLICATION UNDERSTANDING
      ↓
ATTACK-SURFACE GRAPH
      ↓
IDENTITY / AUTHORIZATION MODEL
      ↓
WORKFLOW / STATE MODEL
      ↓
SECURITY HYPOTHESES
      ↓
METHOD SELECTION
      ↓
MULTI-METHOD TESTING
      ↓
OBSERVATION
      ↓
CORRELATION
      ↓
VALIDATION
      ↓
IMPACT ANALYSIS
      ↓
ADVERSARIAL REVIEW
      ↓
FINDING
      ↓
REPORT + EVIDENCE
      ↓
KNOWLEDGE EXTRACTION
      ↓
NEW HYPOTHESES
      ↺
```

---

# 2. V3 Transformation

## V2-style model

```text
Target
 ↓
Recon
 ↓
Known vulnerability checks
 ↓
Tool output
 ↓
Finding
```

## V3 model

```text
Target
 ↓
Discover
 ↓
Understand
 ↓
Model
 ↓
Hypothesize
 ↓
Select multiple methods
 ↓
Test
 ↓
Correlate
 ↓
Challenge
 ↓
Validate
 ↓
Measure impact
 ↓
Report
 ↓
Learn
 ↓
Search for missed areas
 ↺
```

V3 is therefore not simply:

> "More scanners."

It is:

> **A security research system that continuously constructs and tests a model of an authorized application.**

---

# 3. Non-Negotiable Engineering Rules

## 3.1 Inspect the existing repository first

The implementation agent MUST inspect the actual Axxxa_Hunter repository before changing architecture.

Determine:

- existing agents
- existing tools
- entry points
- orchestration
- configuration
- prompts
- skill files
- vulnerability modules
- databases
- queues
- report generation
- browser automation
- HTTP clients
- source-code analysis
- existing RAG/knowledge functionality
- logging
- tests
- deployment
- CLI/UI
- current Web3/security integrations

Never invent existing capabilities.

Create:

```text
docs/V3_REPOSITORY_FORENSICS.md
```

containing:

- current architecture
- current modules
- current agents
- current tools
- current data flow
- current limitations
- reusable components
- replacement candidates
- compatibility risks
- migration plan

---

# 4. V3 Architecture

```text
                         ┌─────────────────────┐
                         │   AUTHORIZED TARGET │
                         └──────────┬──────────┘
                                    ↓
                         ┌─────────────────────┐
                         │ SCOPE ENFORCEMENT   │
                         └──────────┬──────────┘
                                    ↓
                         ┌─────────────────────┐
                         │ DISCOVERY ENGINE    │
                         └──────────┬──────────┘
                                    ↓
                    ┌───────────────┼───────────────┐
                    ↓               ↓               ↓
                 WEB/API         BROWSER          SOURCE
                    ↓               ↓               ↓
                    └───────────────┼───────────────┘
                                    ↓
                       APPLICATION MODEL BUILDER
                                    ↓
             ┌──────────────────────┼──────────────────────┐
             ↓                      ↓                      ↓
       ATTACK SURFACE         IDENTITY MODEL          WORKFLOW MODEL
             ↓                      ↓                      ↓
             └──────────────────────┼──────────────────────┘
                                    ↓
                         SECURITY KNOWLEDGE
                                    ↓
                         HYPOTHESIS ENGINE
                                    ↓
                           TEST PLANNER
                                    ↓
                         METHOD ORCHESTRATOR
                                    ↓
             ┌──────────────────────┼──────────────────────┐
             ↓                      ↓                      ↓
         HTTP/API              BROWSER                 SOURCE
         TESTING               TESTING                 ANALYSIS
             ↓                      ↓                      ↓
             └──────────────────────┼──────────────────────┘
                                    ↓
                         EVIDENCE / OBSERVATION
                                    ↓
                           CORRELATION ENGINE
                                    ↓
                         ADVERSARIAL REVIEWER
                                    ↓
                         VALIDATION ENGINE
                                    ↓
                          IMPACT / CHAIN ENGINE
                                    ↓
                           REPORTING ENGINE
                                    ↓
                      KNOWLEDGE UPDATE ENGINE
                                    ↓
                           MISSED-BUG ENGINE
                                    ↺
```

---

# 5. Five Core Brains

## 5.1 Discovery Brain

Question:

> What exists?

Discovers and maps:

- domains
- subdomains
- hosts
- services
- technologies
- frameworks
- CDNs
- reverse proxies
- WAF indicators
- web applications
- APIs
- REST endpoints
- GraphQL
- WebSockets
- SSE where applicable
- webhooks
- JavaScript
- source maps
- forms
- parameters
- cookies
- headers
- uploads
- downloads
- files
- routes
- authentication surfaces
- administrative functionality
- integrations
- asynchronous workflows

Discovery must track confidence:

```text
CONFIRMED
PROBABLE
POSSIBLE
UNKNOWN
```

---

# 6. Application Understanding Brain

Question:

> How does the application work?

Build an application model from:

- navigation
- routes
- HTTP traffic
- browser behavior
- JavaScript
- API schemas
- source code when authorized
- forms
- workflows
- error behavior
- object relationships
- roles
- tenants
- state transitions
- integrations

The model should explain:

```text
User
 ↓
UI
 ↓
API
 ↓
Service
 ↓
Database / Queue / Worker
 ↓
External integration
```

---

# 7. Attack-Surface Graph

Create a graph containing entities such as:

```text
Domain
Subdomain
Host
Port
Service
Technology
Application
Route
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
Upload
Object
User
Role
Tenant
Workflow
Authentication State
Integration
Queue
Worker
Vulnerability Candidate
Finding
Evidence
```

Example relationships:

```text
domain → subdomain
subdomain → application
application → endpoint
endpoint → parameter
endpoint → authentication state
endpoint → object
object → tenant
user → role
role → permission
finding → endpoint
finding → evidence
finding → attack chain
```

Every node and edge should have provenance and confidence.

---

# 8. Identity Matrix Engine

Model multiple authorized identities where available.

Examples:

```text
Anonymous
User A
User B
Admin
Manager
Employee
Support
Service Account
Tenant A
Tenant B
Verified
Unverified
Suspended
Invited
Expired
MFA-enabled
MFA-disabled
```

Build a matrix:

```text
                 Object A   Object B   Object C
User A              ✓          ?          ?
User B              ?          ✓          ?
Admin               ?          ?          ?
Tenant A            ✓          ?          ?
Tenant B            ?          ✓          ?
```

Test authorization boundaries for:

- read
- create
- update
- delete
- export
- download
- bulk operations
- nested objects
- alternate endpoints
- alternate APIs
- GraphQL
- WebSockets
- asynchronous workers

Only mark an authorization failure confirmed when evidence demonstrates unauthorized access or action.

---

# 9. State-Machine Engine

Represent workflows as:

```text
STATE A
  ↓ action
STATE B
  ↓ action
STATE C
```

Examples:

```text
REGISTERED
 ↓
VERIFIED
 ↓
AUTHENTICATED
 ↓
PROFILE_COMPLETE
 ↓
ACTION_ALLOWED
```

Research transitions such as:

```text
A → B → C
A → C
A → B → D
repeat B
expired state → action
old session → new state
new session → old state
parallel state changes
alternate API state changes
```

The engine must identify security invariants such as:

```text
Only verified users can perform X.
Only tenant members can access Y.
Only owners can modify Z.
Only admins can perform A.
Action B must happen after action C.
```

Then compare expected invariants against observed behavior.

---

# 10. Negative-Space Engine

This is a core V3 capability.

Instead of only asking:

> "What happens when I send this input?"

ask:

> **"What security control should exist here, and is it actually enforced?"**

For every sensitive operation:

```text
EXPECTED SECURITY PROPERTY
          ↓
OBSERVED PROPERTY
          ↓
DIFFERENCE
          ↓
HYPOTHESIS
          ↓
VALIDATION
```

Examples:

```text
Expected:
Only verified users can perform action.

Observed:
Unverified user can perform action.

→ verification-state hypothesis
```

```text
Expected:
Tenant A cannot read Tenant B object.

Observed:
Tenant B object is readable.

→ tenant-isolation hypothesis
```

This engine is especially important for business logic and authorization.

---

# 11. Hypothesis Engine

The hypothesis engine is the central V3 brain.

It must NOT simply execute every scanner.

For each feature:

```text
OBSERVATION
    ↓
CONTEXT
    ↓
TRUST BOUNDARIES
    ↓
SECURITY ASSUMPTIONS
    ↓
HYPOTHESES
    ↓
PRIORITIZATION
    ↓
TEST METHODS
```

Example:

```text
Feature:
Customer export

Observations:
User selects object IDs.
Export is asynchronous.
Export file is later downloaded.

Hypotheses:

H1 authorization inconsistency
H2 cross-tenant object access
H3 bulk-operation authorization weakness
H4 download authorization weakness
H5 worker authorization mismatch
H6 stale-object access
H7 alternate API exposure
```

Each hypothesis must have:

```text
id
vulnerability_class
target_surface
reason
preconditions
expected_security_property
test_methods
evidence_required
validation_method
impact_model
confidence
priority
```

---

# 12. Method Selection Engine

For every hypothesis, select applicable methods.

Method families include:

```text
HTTP request testing
Parameter mutation
Request/response differential analysis
Browser interaction
DOM analysis
JavaScript analysis
Source-to-sink analysis
API schema analysis
GraphQL analysis
WebSocket analysis
Authentication-state comparison
Authorization matrix testing
Workflow/state testing
Concurrency testing
Configuration analysis
Technology-specific analysis
Passive correlation
Safe active validation
```

The planner should select methods based on:

```text
technology
attack surface
authentication state
input context
application behavior
known research patterns
previous observations
risk
test budget
```

---

# 13. Multi-Method Testing

A vulnerability hypothesis should not depend on one detector when multiple safe methods are applicable.

Example:

```text
Candidate XSS
      ↓
reflection analysis
      +
context analysis
      +
source-to-sink analysis
      +
browser observation
      +
stored-content verification
      ↓
correlation
      ↓
validation
```

The same philosophy applies to other vulnerability classes.

---

# 14. Comprehensive Vulnerability Research Matrix

V3 must preserve existing repository capabilities and expand coverage where applicable.

Minimum taxonomy:

## Injection

- SQL injection
- NoSQL injection
- command injection
- expression injection
- template injection
- LDAP injection
- XPath injection
- header injection
- CRLF/response splitting
- HTML injection

## Client-side

- reflected XSS
- stored XSS
- DOM XSS
- client-side redirects
- DOM clobbering where applicable
- postMessage trust issues
- unsafe client-side sinks
- client-side prototype pollution

## Access Control

- IDOR
- BOLA
- BFLA
- privilege escalation
- tenant isolation
- object ownership failures
- function-level authorization
- workflow authorization
- bulk-operation authorization

## Authentication

- authentication bypass
- session weaknesses
- session fixation
- session invalidation
- password reset weaknesses
- account recovery weaknesses
- email/identity-change weaknesses
- MFA workflow weaknesses
- verification-state weaknesses

## Token / Federation

- JWT security issues
- OAuth security issues
- SSO/session binding issues
- token audience/issuer problems
- token lifecycle weaknesses

## Server-Side

- SSRF
- XXE
- unsafe deserialization
- file inclusion
- path traversal
- insecure file processing
- server-side template injection
- unsafe URL fetching

## API

- REST authorization
- GraphQL authorization
- GraphQL query abuse
- WebSocket authorization
- API object exposure
- excessive data exposure
- mass assignment
- unsafe bulk operations
- API workflow weaknesses

## Business Logic

- workflow bypass
- state transition flaws
- quota bypass
- verification bypass
- ownership bypass
- transaction/workflow inconsistencies
- replay behavior
- duplicate-action issues
- race conditions

## HTTP Infrastructure

- request smuggling
- cache poisoning
- cache deception
- parameter pollution
- proxy/parser discrepancies
- host/header trust problems
- open redirects

## Information / Secrets

- exposed secrets
- source maps
- debug information
- configuration exposure
- sensitive error messages
- backup files
- public files
- unintended API data

## Cloud / Infrastructure

- cloud asset exposure
- storage exposure
- IAM-related application exposure
- container/Kubernetes exposure
- CI/CD security issues
- DNS/subdomain takeover
- exposed management surfaces

## AI/LLM Applications

Where the target legitimately exposes AI functionality:

- prompt injection
- indirect prompt injection
- sensitive-data exposure
- unsafe tool invocation
- excessive agency
- RAG trust-boundary failures
- AI authorization failures
- output-to-dangerous-sink flows
- memory/context isolation issues
- multimodal input trust issues

Testing must remain controlled and evidence-driven.

---

# 15. Vulnerability Engine Contract

Every vulnerability engine should implement a common model:

```text
name()
applicable_surfaces()
prerequisites()
generate_hypotheses()
select_methods()
run_tests()
collect_observations()
correlate()
validate()
assess_impact()
generate_finding()
```

Conceptual structure:

```python
class VulnerabilityEngine:
    def applicable_surfaces(self, application_model): ...
    def prerequisites(self, context): ...
    def generate_hypotheses(self, context): ...
    def select_methods(self, hypothesis): ...
    def run_tests(self, hypothesis): ...
    def collect_observations(self): ...
    def correlate(self): ...
    def validate(self): ...
    def assess_impact(self): ...
    def generate_finding(self): ...
```

---

# 16. Security Knowledge Engine

The knowledge engine is not a payload dump.

It stores reusable security research patterns.

Each knowledge item should contain:

```text
id
source
source_type
title
published_at
updated_at
vulnerability_class
attack_surface
application_context
input_location
technology
security_assumption
technique
detection_signal
validation_method
impact
prerequisites
limitations
confidence
provenance
license_notes
last_verified
```

Knowledge should represent:

```text
Application Context
        ↓
Attack Surface
        ↓
Observation
        ↓
Hypothesis
        ↓
Testing Method
        ↓
Evidence
        ↓
Validation
        ↓
Impact
```

Not merely:

```text
payload → bug
```

---

# 17. Public Security Research Ingestion

Authorized/public research sources can be transformed into structured knowledge.

Potential sources:

- OWASP testing guidance
- PortSwigger Web Security Academy
- CVE/NVD
- vendor advisories
- public vulnerability disclosures
- public security research
- security-tool documentation
- public GitHub security research

Pipeline:

```text
SOURCE
 ↓
FETCH
 ↓
PARSE
 ↓
NORMALIZE
 ↓
DEDUPLICATE
 ↓
CLASSIFY
 ↓
EXTRACT SECURITY PATTERN
 ↓
STORE PROVENANCE
 ↓
CONFIDENCE
 ↓
REVIEW
 ↓
LAB VALIDATION
 ↓
KNOWLEDGE ENTRY
```

Respect source licenses, access restrictions, robots/rate limits, and attribution requirements.

Do not blindly copy reports into prompts.

---

# 18. Security Research Lab

Create isolated vulnerable applications for regression and knowledge validation.

Lab categories should cover:

```text
Authentication
Authorization
IDOR/BOLA
XSS
SQLi
SSRF
XXE
SSTI
Command Injection
Deserialization
File Upload
Path Traversal
GraphQL
WebSockets
OAuth
JWT
CSRF
CORS
Race Conditions
Business Logic
Prototype Pollution
Cache Issues
Request Parsing
AI/LLM Security
Multi-Tenancy
```

Each lab case should define:

```text
application
setup
vulnerability
expected evidence
expected non-findings
required authentication
test oracle
cleanup
```

Never validate knowledge against arbitrary third-party systems.

---

# 19. Evidence Engine

Every candidate gets structured evidence.

Required fields:

```text
test_id
finding_id
timestamp
target
scope
asset
endpoint
method
parameter
authentication_state
identity
role
tenant
technique
tool
request_reference
response_reference
browser_reference
source_reference
observation
expected_behavior
actual_behavior
validation_status
impact_evidence
redaction_status
```

Evidence must be:

- reproducible
- timestamped
- attributable to a test
- redacted
- scope-aware
- linked to the exact observation

Never expose credentials, API keys, session tokens or secrets in reports.

---

# 20. Finding Lifecycle

```text
DISCOVERED
    ↓
CANDIDATE
    ↓
NEEDS_VALIDATION
    ↓
VALIDATED
    ↓
IMPACT_VERIFIED
```

Alternative:

```text
CANDIDATE
    ↓
FALSE_POSITIVE
```

A suspicious response is not automatically a vulnerability.

---

# 21. Adversarial Reviewer

Every important finding should pass a challenge stage.

Questions:

```text
Can this be reproduced?

What other explanation exists?

Is authorization genuinely bypassed?

Is the required attacker state available?

Is the behavior security-relevant?

Is the result caused by a test artifact?

Is there a compensating control?

What evidence is missing?

Does the claimed impact actually occur?

Can another independent method corroborate it?
```

The reviewer should be able to downgrade a candidate back to:

```text
NEEDS_VALIDATION
```

rather than forcing a finding.

---

# 22. Correlation Engine

Different tools may discover the same issue.

Example:

```text
Tool A → endpoint anomaly
Tool B → source-to-sink path
Tool C → browser behavior
Tool D → authorization difference
```

Merge them into:

```text
ONE FINDING
    ├── Evidence A
    ├── Evidence B
    ├── Evidence C
    └── Evidence D
```

Correlation keys should include:

```text
asset
endpoint
parameter
object
vulnerability class
root cause
authentication context
technology
workflow
```

---

# 23. Attack-Chain Engine

Only create chains supported by evidence.

Model:

```text
Finding A
   ↓
requires
   ↓
Finding B
   ↓
enables
   ↓
Finding C
```

For every chain:

```text
Prerequisite
Transition
Evidence
Impact
Confidence
```

Do not turn hypothetical relationships into confirmed exploitation claims.

---

# 24. Browser Research Engine

For browser-accessible applications, support:

```text
navigation
forms
authentication states
cookies
storage
DOM
JavaScript
network traffic
client-side routing
event behavior
postMessage
iframes
uploads
downloads
dynamic rendering
```

Correlate:

```text
browser action
 ↓
network request
 ↓
API endpoint
 ↓
server response
 ↓
DOM change
 ↓
source/sink relationship
```

---

# 25. Source Analysis Engine

When source code is legitimately available:

Build:

```text
SOURCE
 ↓
ENTRY POINT
 ↓
DATA FLOW
 ↓
TRANSFORMATION
 ↓
SANITIZATION
 ↓
STORAGE
 ↓
SINK
```

Support correlation with runtime evidence.

Do not treat a dangerous-looking function call alone as a confirmed vulnerability.

---

# 26. API Universe

For every API, map:

```text
Endpoint
Method
Authentication
Authorization
Object
Parameters
Types
Relationships
Error behavior
Pagination
Filtering
Sorting
Bulk operations
State changes
Rate limits
```

Then identify equivalent functionality across:

```text
Web UI
REST
GraphQL
WebSocket
Mobile/API clients
Background workers
```

Security controls should be compared across interfaces.

---

# 27. Business Logic Research Agent

This agent focuses on what the product actually does.

Process:

```text
UNDERSTAND BUSINESS FUNCTION
 ↓
IDENTIFY VALUABLE OBJECTS
 ↓
IDENTIFY ACTORS
 ↓
IDENTIFY ACTIONS
 ↓
IDENTIFY INVARIANTS
 ↓
IDENTIFY STATES
 ↓
GENERATE UNUSUAL VALID SEQUENCES
 ↓
TEST
 ↓
VALIDATE IMPACT
```

This is deliberately different from signature-based scanning.

---

# 28. Missed-Bug Engine

After a scan, Axxxa must ask:

```text
What did we not test?
Why?
What assumptions did we make?
Which endpoints are weakly covered?
Which parameters are untested?
Which roles were unavailable?
Which workflows were incomplete?
Which technologies were not analyzed?
Which vulnerability classes were blocked?
Which hypotheses remain unresolved?
```

Then create a second-pass plan.

```text
PASS 1
 ↓
Results
 ↓
New observations
 ↓
New hypotheses
 ↓
PASS 2
 ↓
New observations
 ↓
New hypotheses
 ↓
PASS 3
```

Stop when coverage/budget criteria are reached.

---

# 29. Coverage Matrix

Axxxa must report:

```text
TESTED
NOT TESTED
NOT APPLICABLE
BLOCKED
AUTH REQUIRED
SOURCE REQUIRED
BROWSER REQUIRED
MANUAL REVIEW REQUIRED
```

Coverage dimensions:

```text
asset
endpoint
parameter
HTTP method
authentication state
identity
role
tenant
workflow
technology
vulnerability class
testing method
```

The report must make blind spots visible.

---

# 30. Continuous Hunting Mode

Support long-running research jobs.

Required:

- persistent job queue
- checkpoints
- retries
- pause/resume
- crash recovery
- budgets
- rate limits
- scope revalidation
- duplicate-test suppression
- result persistence
- incremental reports
- knowledge updates
- coverage tracking

The system should never continuously repeat an identical test without a reason.

---

# 31. Test Budget

Every job should have:

```text
time budget
request budget
browser budget
LLM budget
tool budget
concurrency budget
storage budget
```

Hypothesis priority should consider:

```text
security relevance
attack-surface relevance
evidence quality
knowledge confidence
novelty
test cost
risk
previous results
```

---

# 32. Safety and Scope Enforcement

Every active action must pass:

```text
TARGET IN SCOPE?
       ↓
IDENTITY AUTHORIZED?
       ↓
ACTION ALLOWED?
       ↓
TEST SAFE?
       ↓
BUDGET AVAILABLE?
       ↓
EXECUTE
```

Maintain:

```text
scope allowlist
excluded assets
excluded paths
rate limits
test intensity
identity restrictions
audit log
kill switch
```

The system must default to safe behavior when scope is ambiguous.

---

# 33. Self-Security of Axxxa

Protect:

- credentials
- API keys
- session tokens
- target data
- reports
- knowledge database
- source code
- logs
- tool execution
- browser profiles

Implement:

```text
least privilege
secret redaction
encrypted storage where appropriate
sandboxed tool execution
audit logs
access control
credential isolation
safe temporary files
```

---

# 34. Agent Architecture

Recommended logical agents:

```text
1. Scope & Safety Officer
2. Reconnaissance Researcher
3. Application Cartographer
4. Technology Analyst
5. Identity & Authorization Researcher
6. Workflow/Business Logic Researcher
7. Injection Researcher
8. Server-Side Researcher
9. Client-Side/Browser Researcher
10. API/GraphQL Researcher
11. Infrastructure Researcher
12. AI/LLM Security Researcher
13. Hypothesis Planner
14. Evidence Analyst
15. Adversarial Reviewer
16. Validation Officer
17. Attack-Chain Analyst
18. Report Engineer
19. Knowledge Curator
20. Missed-Bug Researcher
```

These are logical responsibilities. Reuse existing agents where possible instead of duplicating functionality.

---

# 35. Tool Orchestration

Tools must be treated as instruments, not as the brain.

Architecture:

```text
Researcher
   ↓
Hypothesis
   ↓
Planner
   ↓
Tool selection
   ↓
Tool execution
   ↓
Observation
   ↓
Correlation
   ↓
Validation
```

Every tool invocation should record:

```text
tool
version
arguments
target
timestamp
result reference
exit status
```

---

# 36. Hallucination Controls

AI must never invent:

- endpoints
- vulnerabilities
- evidence
- permissions
- impact
- successful exploitation
- source-code paths
- browser behavior

If information is unknown:

```text
UNKNOWN
```

If evidence is incomplete:

```text
NEEDS_VALIDATION
```

If an action was not tested:

```text
NOT_TESTED
```

---

# 37. Learning Loop

After every validated finding:

```text
FINDING
 ↓
ROOT CAUSE
 ↓
SECURITY PATTERN
 ↓
KNOWLEDGE ENTRY
 ↓
LAB CASE
 ↓
REGRESSION TEST
 ↓
FUTURE HYPOTHESIS
```

False positives can also become knowledge:

```text
FALSE POSITIVE
 ↓
WHY MISLEADING
 ↓
DETECTION IMPROVEMENT
 ↓
REGRESSION TEST
```

This makes Axxxa progressively more precise.

---

# 38. Research Memory

Maintain memory at several levels:

## Target memory

```text
assets
technologies
endpoints
roles
workflows
known findings
coverage
```

## Session memory

```text
tests
observations
hypotheses
decisions
```

## Global security knowledge

```text
vulnerability patterns
technology behaviors
validation patterns
false-positive patterns
lab results
```

Separate target-specific information from reusable global knowledge.

---

# 39. Professional Reporting

Report structure:

```text
Executive Summary

Scope

Testing Period

Assets

Technology Map

Attack Surface

Authentication Model

Authorization Model

Workflow Model

Coverage

Validated Findings

Finding Details

Evidence

Validation

Impact

Attack Chains

Tested Methods

Not Tested

Blocked Tests

Manual Review Items

False Positives / Discarded Candidates

Recommendations

Appendices
```

Each finding should contain:

```text
Title
Class
Severity
Confidence
Asset
Endpoint
Parameter/Object
Authentication State
Role
Tenant
Description
Security Assumption
Observed Behavior
Evidence
Validation
Impact
Root Cause
Reproduction
Remediation
Related Findings
Coverage Notes
```

---

# 40. Severity and Confidence

Keep these separate.

Example:

```text
Severity:
Impact if real

Confidence:
How strongly the evidence supports the finding
```

Do not let a model assign severity from wording alone.

Use evidence and explicit criteria.

---

# 41. V3 Database Model

Minimum entities:

```text
Target
ScopeRule
Asset
Technology
Endpoint
Parameter
Request
Response
Identity
Role
Tenant
Workflow
State
Hypothesis
Test
Observation
Evidence
Finding
AttackChain
KnowledgeItem
Source
LabCase
RegressionTest
CoverageRecord
Job
ToolExecution
AuditEvent
```

Relationships must preserve provenance.

---

# 42. Suggested Internal APIs

Examples:

```text
POST /targets
POST /jobs
POST /jobs/{id}/pause
POST /jobs/{id}/resume
GET  /jobs/{id}
GET  /targets/{id}/attack-surface
GET  /targets/{id}/coverage
GET  /targets/{id}/hypotheses
GET  /targets/{id}/findings
GET  /findings/{id}/evidence
GET  /knowledge/search
POST /knowledge/review
GET  /research/status
```

Exact implementation must follow the existing repository architecture.

---

# 43. Repository Structure

Adapt to the existing repo rather than blindly replacing it.

A possible V3 structure:

```text
axxxa_hunter/
├── core/
│   ├── scope/
│   ├── orchestration/
│   ├── state/
│   ├── budgets/
│   └── events/
│
├── discovery/
│   ├── web/
│   ├── api/
│   ├── browser/
│   ├── technology/
│   └── attack_surface/
│
├── modeling/
│   ├── application/
│   ├── identity/
│   ├── authorization/
│   ├── workflow/
│   └── dataflow/
│
├── hypotheses/
│   ├── generator/
│   ├── prioritizer/
│   └── planner/
│
├── vulnerabilities/
│   ├── injection/
│   ├── xss/
│   ├── access_control/
│   ├── auth/
│   ├── api/
│   ├── server_side/
│   ├── business_logic/
│   ├── infrastructure/
│   └── ai_security/
│
├── testing/
│   ├── http/
│   ├── browser/
│   ├── source/
│   ├── api/
│   └── concurrency/
│
├── evidence/
├── validation/
├── correlation/
├── attack_chains/
├── knowledge/
├── research_lab/
├── reporting/
├── storage/
├── agents/
├── tools/
├── tests/
└── docs/
```

Use existing names if the repository already has an established structure.

---

# 44. Implementation Waves

## Wave 0 — Repository Forensics

Deliver:

```text
V3_REPOSITORY_FORENSICS.md
```

No major code changes before understanding the existing system.

---

## Wave 1 — Core Infrastructure

Implement:

- scope engine
- event bus
- job state
- persistence
- budgets
- audit logs
- configuration
- safe execution

Acceptance:

- jobs survive restart
- scope is enforced
- every active action is logged

---

## Wave 2 — Application Model

Implement:

- attack-surface graph
- identity graph
- authorization graph
- workflow graph
- data-flow graph

Acceptance:

- application can be represented structurally
- graph nodes have provenance

---

## Wave 3 — Discovery

Implement comprehensive:

- web discovery
- API discovery
- browser discovery
- technology identification
- JavaScript/source-map discovery
- parameter discovery

Acceptance:

- discovery results are deduplicated and correlated

---

## Wave 4 — Knowledge Engine

Implement:

- knowledge schema
- ingestion
- normalization
- deduplication
- provenance
- confidence
- semantic retrieval
- review workflow

Acceptance:

- public research becomes structured security patterns

---

## Wave 5 — Hypothesis Engine

Implement:

- security-assumption extraction
- hypothesis generation
- prioritization
- method selection
- hypothesis persistence

Acceptance:

- each meaningful attack surface receives applicable hypotheses

---

## Wave 6 — Vulnerability Engines

Implement/upgrade all applicable vulnerability modules.

Acceptance for every module:

```text
Applicable surfaces
Input locations
Prerequisites
Multiple methods
Detection signals
Evidence requirements
Validation
Impact
Limitations
Regression cases
```

---

## Wave 7 — Browser + Source Correlation

Implement:

```text
HTTP ↔ Browser ↔ Source
```

Acceptance:

- evidence from different modalities can form one investigation

---

## Wave 8 — Validation + Adversarial Review

Implement:

- evidence validator
- false-positive engine
- adversarial reviewer
- impact verifier

Acceptance:

- suspicious observations do not automatically become findings

---

## Wave 9 — Missed-Bug Research

Implement:

- coverage engine
- unresolved hypothesis tracker
- second-pass planner
- blind-spot detector

Acceptance:

- every job produces a machine-readable coverage report

---

## Wave 10 — Research Lab

Implement:

- vulnerable labs
- test fixtures
- regression suite
- knowledge validation

Acceptance:

- known vulnerable lab cases are detected
- fixed false positives remain fixed

---

## Wave 11 — Attack Chains + Reporting

Implement:

- finding correlation
- evidence-supported attack chains
- professional reports
- machine-readable exports

---

## Wave 12 — Continuous Research

Implement:

- scheduled knowledge updates
- new pattern extraction
- regression generation
- long-running research
- incremental coverage

---

# 45. Testing Strategy

## Unit Tests

Test:

- scope
- graph operations
- hypothesis generation
- prioritization
- validation
- evidence
- correlation
- knowledge retrieval

## Integration Tests

Test:

```text
Discovery → Model
Model → Hypothesis
Hypothesis → Test
Test → Evidence
Evidence → Validation
Validation → Finding
Finding → Report
Finding → Knowledge
```

## End-to-End Lab Tests

Use isolated vulnerable applications.

Every supported vulnerability class should have:

```text
positive case
negative case
edge case
false-positive case
```

---

# 46. Coverage Definition of Done

A vulnerability engine is not complete because it can detect one example.

For every engine answer:

```text
What surfaces were tested?

What inputs were tested?

What methods were used?

What technologies were covered?

What authentication states were used?

What identities were compared?

What evidence was collected?

How was the candidate validated?

What impact was demonstrated?

What was not tested?

What prerequisites were missing?

Can it correlate with other findings?

Does it have regression tests?
```

---

# 47. V3 Operating Modes

## Fast Scan

Quick broad coverage.

```text
Discovery
 ↓
high-value hypotheses
 ↓
limited validation
```

## Deep Research

Maximum practical coverage within the authorized scope.

```text
Discovery
 ↓
full modeling
 ↓
all applicable hypotheses
 ↓
multi-method testing
 ↓
validation
 ↓
missed-bug passes
```

## Continuous Research

```text
baseline
 ↓
new discovery
 ↓
new hypotheses
 ↓
new testing
 ↓
knowledge update
 ↓
regression
 ↓
repeat
```

---

# 48. Dashboard

The dashboard should show:

```text
Assets discovered
Endpoints discovered
Parameters discovered
Technologies
Identities
Roles
Tenants
Workflows
Hypotheses generated
Tests executed
Evidence collected
Candidates
Validated findings
False positives
Coverage
Blocked tests
Unresolved hypotheses
Attack chains
Knowledge updates
```

The most important metric is not:

> number of payloads sent.

It is:

> **How much of the application's security-relevant attack surface has been meaningfully investigated and validated?**

---

# 49. V3 Research Quality Metrics

Track:

```text
Discovery completeness
Endpoint coverage
Parameter coverage
Identity coverage
Workflow coverage
Vulnerability-class coverage
Method coverage
Evidence completeness
Validation rate
False-positive rate
Duplicate rate
Regression rate
Knowledge reuse
Novel hypothesis rate
Unresolved hypothesis count
```

Do not optimize solely for number of findings.

---

# 50. What "Extreme" Means in V3

Extreme does NOT mean:

```text
send more requests
use more payloads
run every scanner
generate more findings
```

Extreme means:

```text
Understand more
Model more
Hypothesize more intelligently
Test more applicable methods
Correlate more evidence
Validate harder
Explore deeper workflows
Compare more security contexts
Identify blind spots
Learn from research
Learn from failures
Repeat intelligently
```

---

# 51. Final V3 Mental Model

The hunter should behave conceptually like:

```text
                 ┌────────────────────┐
                 │      OBSERVE       │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │    UNDERSTAND      │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │       MODEL        │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │     HYPOTHESIZE    │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │       TEST         │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │      CORRELATE     │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │      CHALLENGE     │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │      VALIDATE      │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │   MEASURE IMPACT   │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │      REPORT        │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │       LEARN        │
                 └─────────┬──────────┘
                           ↓
                 ┌────────────────────┐
                 │   FIND WHAT WAS    │
                 │      MISSED        │
                 └─────────┬──────────┘
                           │
                           └────────↺
```

---

# 52. Final Product Definition

After V3 implementation, Axxxa_Hunter should be architecturally capable of:

1. Discovering a broad web application's attack surface.
2. Building an application model rather than treating endpoints independently.
3. Understanding authentication, authorization, roles and tenant boundaries.
4. Reconstructing important workflows and state transitions.
5. Generating security hypotheses from observations and security assumptions.
6. Selecting multiple applicable testing methods.
7. Combining HTTP, API, browser and source evidence.
8. Testing a broad vulnerability taxonomy.
9. Distinguishing observations from validated findings.
10. Challenging its own findings.
11. Measuring actual impact.
12. Correlating related findings.
13. Constructing only evidence-supported attack chains.
14. Reporting tested and untested areas.
15. Learning structured security patterns from public research.
16. Validating knowledge in isolated labs.
17. Turning findings and false positives into regression knowledge.
18. Performing additional research passes to find blind spots.
19. Running persistently with checkpoints and budgets.
20. Improving future hypothesis generation from validated knowledge.

---

# 53. Developer Instruction

The implementation agent must treat this document as an engineering specification, not as a request to create superficial placeholder modules.

Before implementation:

```text
1. Inspect repository.
2. Map current architecture.
3. Identify reusable code.
4. Identify gaps against V3.
5. Produce migration plan.
6. Implement infrastructure.
7. Implement modeling.
8. Implement knowledge.
9. Implement hypotheses.
10. Implement testing.
11. Implement validation.
12. Implement missed-bug research.
13. Implement reporting.
14. Build lab/regression suite.
15. Run end-to-end tests.
16. Document remaining limitations.
```

Do not claim a feature is implemented until it has:

```text
code
tests
integration
observability
documentation
```

Do not fabricate test results.

Do not fabricate vulnerabilities.

Do not claim "100% coverage" or "finds every bug."

The system's goal is:

> **Maximum practical, systematic, evidence-driven security research coverage against explicitly authorized targets.**

---

# 54. V3 End State

The final conceptual transformation is:

```text
Axxxa_Hunter
     │
     ├── Discovery
     ├── Application Understanding
     ├── Attack-Surface Graph
     ├── Identity Graph
     ├── Workflow Graph
     ├── Security Knowledge
     ├── Hypothesis Engine
     ├── Multi-Method Testing
     ├── Browser Analysis
     ├── Source Analysis
     ├── API Analysis
     ├── Evidence Engine
     ├── Validation Engine
     ├── Adversarial Review
     ├── Impact Analysis
     ├── Attack-Chain Analysis
     ├── Coverage Engine
     ├── Missed-Bug Research
     ├── Research Lab
     ├── Regression Knowledge
     └── Continuous Learning
```

### Final principle

**Do not build the world's biggest scanner.**

Build the system that performs the most complete, disciplined and evidence-driven **security investigation** that can practically be automated.

**Axxxa_Hunter V3 = Discover → Understand → Hypothesize → Test → Prove → Learn → Search Again.**

