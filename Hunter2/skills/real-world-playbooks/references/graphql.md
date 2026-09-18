# Real-World Playbook — GraphQL

**Class:** `graphql` · **Coverage-matrix tier:** 1 · **Hunter2:** tools/graphql_audit.sh · /graphql-audit · **Skill:** graphql-audit
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed GraphQL reports peak at **$12,500**. Rewarded across: EXNESS, GitLab, HackerOne, Mail.ru, Mozilla, New Relic, Shopify.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — HackerOne, $12,500 · 180👍 · [3287208](https://hackerone.com/reports/3287208)
- **Unauthenticated RCE in Taskcluster web-server via GraphQL filter argument (sift $where)** — Mozilla, $12,000 · 331👍 · [3782701](https://hackerone.com/reports/3782701)
- **IDOR on GraphQL queries BillingDocumentDownload and BillDetails** — Shopify, $5,000 · 187👍 · [2207248](https://hackerone.com/reports/2207248)
- **Insufficient Type Check on GraphQL leading to Maintainer delete repository** — GitLab, $4,000 · 18👍 · [858671](https://hackerone.com/reports/858671)
- **SSRF in graphQL query (pwapi.ex2b.com)** — EXNESS, $3,000 · 261👍 · [1864188](https://hackerone.com/reports/1864188)
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

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
/v1/explorer
/v1/graphiql
/graph
/graphql
/graphql/console/
/graphql.php
/graphiql
/graphiql.php
```
```
    GET /graphql?query={yourQueryHere}
    GET /graphql?query={__schema{types{name}}}
    GET /graphiql?query={__schema{types{name}}}
    GET /graphql?query=query%20%7B%20user(id:%221%22)%20%7B%20id%20name%20%7D%20%7D
```
```
    POST /graphql/v1 HTTP/1.1
    Host: example.com
    Content-Type: application/json

    {
    "query": "query { user { id name } }"
    }
```
```
?query={__schema}
?query={}
?query={thisdefinitelydoesnotexist}
```
```
{
  "query": "{ __schema { types { name } } }"
}
```
```
fragment+FullType+on+__Type+{++kind++name++description++fields(includeDeprecated%3a+true)+{++++name++++description++++args+{++++++...InputValue++++}++++type+{++++++...TypeRef++++}++++isDeprecated++++deprecationReason++}++inputFields+{++++...InputValue++}++interfaces+{++++...TypeRef++}++enumValues(includeDeprecated%3a+true)+{++++name++++description++++isDeprecated++++deprecationReason++}++possibleTypes+{++++...TypeRef++}}fragment+InputValue+on+__InputValue+{++name++description++type+{++++...TypeRef++}++defaultValue}fragment+TypeRef+on+__Type+{++kind++name++ofType+{++++kind++++name++++ofType+{++++++kind++++++name++++++ofType+{++++++++kind++++++++name++++++++ofType+{++++++++++kind++++++++++name++++++++++ofType+{++++++++++++kind++++++++++++name++++++++++++ofType+{++++++++++++++kind++++++++++++++name++++++++++++++ofType+{++++++++++++++++kind++++++++++++++++name++++++++++++++}++++++++++++}++++++++++}++++++++}++++++}++++}++}}query+IntrospectionQuery+{++__schema+{++++queryType+{++++++name++++}++++mutationType+{++++++name++++}++++types+{++++++...FullType++++}++++directives+{++++++name++++++description++++++locations++++++args+{++++++++...InputValue++++++}++++}++}}
```
```
fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}
fragment InputValue on __InputValue {
  name
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### GraphQL

|ID          |
|------------|
|WSTG-APIT-99|

#### Summary

GraphQL has become very popular in modern APIs. It provides simplicity and nested objects, which facilitate faster development. While every technology has advantages, it can also expose the application to new attack surfaces. The purpose of this scenario is to provide some common misconfigurations and attack vectors on applications that utilize GraphQL. Some vectors are unique to GraphQL (e.g. [Introspection Query](#introspection-queries)) and some are generic to APIs (e.g. [SQL injection](#sql-injection)).

Examples in this section will be based on a vulnerable GraphQL application [poc-graphql](https://github.com/righettod/poc-graphql), which is run in a docker container that maps `localhost:8080/GraphQL` as the vulnerable GraphQL node.

#### Test Objectives

- Assess that a secure and production-ready configuration is deployed.
- Validate all input fields against generic attacks.
- Ensure that proper access controls are applied.

#### How to Test

Testing GraphQL nodes is not very different than testing other API technologies. Consider the following steps:

##### Introspection Queries

Introspection queries are the method by which GraphQL lets you ask what queries are supported, which data types are available, and many more details you will need when approaching a test of a GraphQL deployment.

The [GraphQL website describes Introspection](https://graphql.org/learn/introspection/):

> "It's often useful to ask a GraphQL schema for information about what queries it supports. GraphQL allows us to do so using the introspection system!"

There are a couple of ways to extract this information and visualize the output, as follows.

###### Using Native GraphQL Introspection

The most straightforward way is to send an HTTP request (using a personal proxy) with the following payload, taken from an article on [Medium](https://medium.com/@the.bilal.rizwan/graphql-common-vulnerabilities-how-to-exploit-them-464f9fdce696):

```graphql
query IntrospectionQuery {
  __schema {
    queryType {
      name
    }
    mutationType {
      name
    }
    subscriptionType {
      name
    }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### GraphQL


#### Introduction

GraphQL is **highlighted** as an **efficient alternative** to REST API, offering a simplified approach for querying data from the backend. In contrast to REST, which often necessitates numerous requests across varied endpoints to gather data, GraphQL enables the fetching of all required information through a **single request**. This streamlining significantly **benefits developers** by diminishing the intricacy of their data fetching processes.<sup>[[3]](#references)</sup>

#### GraphQL and Security

GraphQL does not provide application authentication or authorization by itself; developers must enforce those controls in the surrounding application and in resolver logic. Without them, endpoints may expose sensitive information or operations to unauthenticated or unauthorized users.<sup>[[1]](#references)[[6]](#references)</sup>

##### Directory Brute Force Attacks and GraphQL

When looking for exposed GraphQL endpoints, include common paths in content-discovery scans. Practical GraphQL testing guides use paths and probes such as these:<sup>[[4]](#references)[[5]](#references)</sup>

- `/graphql`
- `/graphiql`
- `/graphql.php`
- `/graphql/console`
- `/api`
- `/api/graphql`
- `/graphql/api`

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Introspection on → map hidden mutations → BFLA/IDOR via aliasing
- Batching/alias → brute or DoS; nested query → depth bomb
- Field-level auth gap → read fields the UI hides

## Hunter2 wiring
- **Run:** `tools/graphql_audit.sh · /graphql-audit`
- **Skill:** `graphql-audit`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
