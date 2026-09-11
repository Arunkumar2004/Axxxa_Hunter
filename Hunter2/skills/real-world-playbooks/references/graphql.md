# Real-World Playbook — GraphQL

**Class:** `graphql` · **Coverage-matrix tier:** 1 · **Hunter2:** tools/graphql_audit.sh · /graphql-audit · **Skill:** graphql-audit
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed GraphQL reports peak at **$12,500**. Rewarded across: EXNESS, GitLab, HackerOne, Mail.ru, Mozilla, New Relic, Shopify.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — HackerOne, $12,500 · 175👍 · [3287208](https://hackerone.com/reports/3287208)
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — Mozilla, $12,000 · 270👍 · [3782701](https://hackerone.com/reports/3782701)
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — Shopify, $5,000 · 186👍 · [2207248](https://hackerone.com/reports/2207248)
- **Insufficient Type Check on GraphQL leading to Maintainer delete repository** — GitLab, $4,000 · 16👍 · [858671](https://hackerone.com/reports/858671)
- **SSRF in graphQL query (pwapi.ex2b.com)** — EXNESS, $3,000 · 259👍 · [1864188](https://hackerone.com/reports/1864188)
- **Team object in GraphQL disclosed private_comment** — HackerOne, $2,500 · 146👍 · [978143](https://hackerone.com/reports/978143)
- **Unauthorized user can obtain `report_sources` attribute through Team GraphQL object** — HackerOne, $2,500 · 142👍 · [770209](https://hackerone.com/reports/770209)
- **Private program disclosure via `vpn_suspended` GraphQL query** — HackerOne, $2,500 · 138👍 · [715192](https://hackerone.com/reports/715192)
- **GraphQL field on Team node can be used to determine if External Program runs invite-only program** — HackerOne, $2,500 · 107👍 · [877642](https://hackerone.com/reports/877642)
- **Team object in GraphQL disclosed total number of whitelisted hackers** — HackerOne, $2,500 · 93👍 · [342978](https://hackerone.com/reports/342978)
- **Team object in GraphQL discloses team group names and permissions** — HackerOne, $2,500 · 75👍 · [343464](https://hackerone.com/reports/343464)
- **Access to information about any video and its owner via GraphQL endpoint [dictor.mail.ru]** — Mail.ru, $2,500 · 42👍 · [924914](https://hackerone.com/reports/924914)
- **Undocumented `fileCopy` GraphQL API** — Shopify, $2,000 · 157👍 · [981472](https://hackerone.com/reports/981472)
- **[h1-2102] shopApps query from the graphql at /users/api returns all existing created apps, including private ones** — Shopify, $1,900 · 34👍 · [1085332](https://hackerone.com/reports/1085332)
- **[h1-2102] Stored XSS in product description via `productUpdate` GraphQL query leads to XSS at handshake-web-internal.shopifycloud.com/products/[ID]** — Shopify, $1,600 · 8👍 · [1085546](https://hackerone.com/reports/1085546)
- **H1514 Get access to non public information by pivoting with graphql queries** — Shopify, $1,500 · 14👍 · [423388](https://hackerone.com/reports/423388)
- **H1514 [beerify.shopifycloud.com] GraphQL discloses internal beer consumption** — Shopify, $802 · 57👍 · [419883](https://hackerone.com/reports/419883)
- **[NR Infrastructure] Bypass of #200576 through GraphQL query abuse - allows restricted user access to root account license key** — New Relic, $750 · 5👍 · [276174](https://hackerone.com/reports/276174)

## Chaining — always ask "what does this unlock?"
- Introspection on → map hidden mutations → BFLA/IDOR via aliasing
- Batching/alias → brute or DoS; nested query → depth bomb
- Field-level auth gap → read fields the UI hides

## Hunter2 wiring
- **Run:** `tools/graphql_audit.sh · /graphql-audit`
- **Skill:** `graphql-audit`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
