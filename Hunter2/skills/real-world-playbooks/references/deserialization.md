# Real-World Playbook — Insecure Deserialization

**Class:** `deserialization` · **Coverage-matrix tier:** 2 · **Hunter2:** /deser-hunt · tools/deser_probe.py · **Skill:** deserialization
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Insecure Deserialization

|ID          |
|------------|
|WSTG-INJT-23|

#### Summary

Data serialization is the process of converting an object into a format that can be stored
(for example, in a file or database) or transmitted (for example, over a network) and
reconstructed later. Deserialization is the reverse process: taking data structured from
some format and rebuilding it into an object.

Insecure deserialization occurs when an application deserializes untrusted data without
sufficiently verifying that the resulting data will be valid. Attackers can leverage this
to manipulate serialized objects in order to influence application behavior or trigger
unintended actions during the deserialization process.

The most critical impact of insecure deserialization is remote code execution (RCE).
However, it may also result in denial of service (DoS), authentication bypass, access
control issues, or abuse of application logic.

JSON that is merged into objects in JavaScript runtimes can also enable
[prototype pollution](22-Prototype_Pollution.md). Treat that as a related
test case rather than a separate deserialization format.

#### Test Objectives

- Identify entry points where the application accepts serialized objects from untrusted
  sources (for example, HTTP headers, parameters, or cookies).
- Determine the serialization format used by the application.
- Assess whether serialized input is validated or restricted prior to deserialization.
- Evaluate whether manipulation of serialized data leads to unsafe behavior or security
  impact.

#### How to Test

##### Black-Box Testing

###### Identification of Serialized Data

Identify where the application processes serialized data. Inspect cookies, hidden fields,
API bodies, headers, and file uploads for recognizable patterns, encodings, or structural
characteristics.

###### Java Serialization

Java serialized objects typically begin with the hex bytes `AC ED 00 05`. When base64
encoded, this frequently appears as `rO0`.

```http
Cookie: rememberMe=rO0ABXNyABpY...
```

###### PHP Serialization

PHP serialization is human-readable and uses specific characters to represent data types
(for example, `O` for object, `a` for array, `s` for string).

```http

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Deserialization


#### Basic Information

**Serialization** is understood as the method of converting an object into a format that can be preserved, with the intent of either storing the object or transmitting it as part of a communication process. This technique is commonly employed to ensure that the object can be recreated at a later time, maintaining its structure and state.

**Deserialization**, conversely, is the process that counteracts serialization. It involves taking data that has been structured in a specific format and reconstructing it back into an object.

Deserialization can be dangerous because it potentially **allows attackers to manipulate the serialized data to execute harmful code** or cause unexpected behavior in the application during the object reconstruction process.

#### PHP

In PHP, specific magic methods are utilized during the serialization and deserialization processes:

- `__sleep`: Invoked when an object is being serialized. This method should return an array of the names of all properties of the object that should be serialized. It's commonly used to commit pending data or perform similar cleanup tasks.
- `__wakeup`: Called when an object is being deserialized. It's used to reestablish any database connections that may have been lost during serialization and perform other reinitialization tasks.
- `__unserialize`: This method is called instead of `__wakeup` (if it exists) when an object is being deserialized. It gives more control over the deserialization process compared to `__wakeup`.
- `__destruct`: This method is called when an object is about to be destroyed or when the script ends. It's typically used for cleanup tasks, like closing file handles or database connections.
- `__toString`: This method allows an object to be treated as a string. It can be used for reading a file or other tasks based on the function calls within it, effectively providing a textual representation of the object.

```php

*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Java/PHP/.NET/Python gadget chain → **RCE**
- Serialized cookie/viewstate/blob → tamper → privesc or RCE

## Hunter2 wiring
- **Run:** `/deser-hunt · tools/deser_probe.py`
- **Skill:** `deserialization`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
