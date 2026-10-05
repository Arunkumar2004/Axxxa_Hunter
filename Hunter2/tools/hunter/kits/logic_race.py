"""Business-logic + race-condition depth kit for the Hunter Engine.

This kit covers two classes the target model usually exposes together:

* ``business-logic`` - parameter and workflow tampering: price/amount tampering
  (set to 1, 0, negative, huge, 64-bit overflow), quantity tampering (negative
  -> credit, or beyond a stated limit), currency swap, coupon/discount reuse and
  stacking, step-skip / forced-browsing of a multi-step workflow (jump to the
  final step without its prerequisite), and ownership/role field injection in
  request bodies (``role=admin``, ``is_verified=true``).  Every positive result
  is confirmed by response-diff plus state reasoning, not by a status code.
* ``race-condition`` - endpoints where parallel submits could double-spend or
  bypass a single-use limit (coupon redeem, balance withdraw, vote, invite).

Safety (the README's hard rules, enforced here):

* Every request goes through ``ctx.fetch`` - the kit never touches the network
  directly, which is what keeps it unit-testable offline.
* Any state-changing probe (POST/PUT/PATCH/DELETE) and the race burst run ONLY
  when ``ctx.allow_write`` is True.  A mutation captures the original value
  first and auto-reverts afterwards (PUT/PATCH restores the old body; a created
  object is removed with DELETE - and DELETE only ever touches an object this
  kit itself created).  Without ``allow_write`` the kit performs no request at
  all and instead emits HYPOTHESIS findings (verdict POSSIBLE, confidence
  tentative) describing the exact manual test.
* Bursts use the smallest safe N (``SAFE_BURST`` = 5) and never flood a host;
  out-of-scope hosts are skipped.
* No secrets (auth headers, bearer tokens, full bodies) ever reach a Finding.

The parallel-submit burst reuses the concurrency pattern from
``tools/h1_race.py`` (``test_bounty_race`` / ``test_2fa_rate_limit``): a
``threading.Barrier`` releases every worker at the same instant so the requests
truly overlap in the server's check-then-act window.  Unlike the original - a
HackerOne-specific CLI that calls ``urllib`` directly - every request here is
issued through ``ctx.fetch``, so the burst stays SSRF-safe and offline-mockable.
"""
from __future__ import annotations

import json
import re
import threading
from urllib.parse import urlsplit

from tools.hunter.contract import (
    Finding,
    HuntContext,
    V_CONFIRMED,
    V_POSSIBLE,
    register,
)

# --------------------------------------------------------------------------
# tunables and vocabularies
# --------------------------------------------------------------------------
SAFE_BURST = 5  # smallest safe N for a race burst; deliberately tiny - never DoS

# Field-name families (matched token-wise so "unit_price"/"grandTotal" match but
# "discount" does not get mistaken for a quantity "count").
MONEY_FIELDS = ("price", "amount", "total", "subtotal", "grandtotal",
                "grand_total", "cost", "unit_price", "unitprice", "fee",
                "value", "balance", "payable", "paise", "charge", "sum")
QTY_FIELDS = ("qty", "quantity", "count", "units", "seats", "items",
              "num_items", "numitems", "stock")
CURRENCY_FIELDS = ("currency", "ccy", "cur")
# bare "code" is intentionally excluded here - too broad; a coupon is detected by
# an unambiguous name so it never collides with a generic "code" field.
COUPON_FIELDS = ("coupon", "coupon_code", "couponcode", "promo", "promo_code",
                 "promocode", "discount_code", "discountcode", "voucher")
IDENTITY_FIELDS = ("role", "email", "username", "user_id", "userid", "owner",
                   "account", "account_id", "is_admin", "is_verified",
                   "verified", "is_staff", "privilege", "account_type",
                   "member_id", "admin")
ACCOUNT_HINTS = ("user", "users", "account", "accounts", "profile", "member",
                 "members", "register", "signup", "sign_up", "role", "roles",
                 "team", "org", "tenant", "staff", "admin", "/me")
RACE_HINTS = ("redeem", "redemption", "withdraw", "withdrawal", "payout",
              "cashout", "cash_out", "vote", "upvote", "downvote", "invite",
              "claim", "transfer", "giftcard", "gift_card", "voucher", "points",
              "refer", "referral", "coupon", "spend", "like", "follow")
WORKFLOW_PATH_RE = re.compile(
    r"/(checkout|wizard|onboarding|kyc|application|signup|enrol|enroll)/",
    re.IGNORECASE,
)
FINAL_STEP_WORDS = ("confirm", "complete", "finish", "finalize", "finalise",
                    "review", "submit", "place", "success", "done", "pay",
                    "activate")

ROLE_INJECT = {
    "role": "admin",
    "is_admin": True,
    "is_staff": True,
    "is_verified": True,
    "verified": True,
    "account_type": "admin",
    "privilege": "admin",
}

# Price tamper values: one unit, zero, negative, huge, 64-bit overflow boundary.
MONEY_TAMPERS = (1, 0, -1, 99_999_999_999, 2 ** 63)
# Quantity tamper values: negative (credit), zero, far beyond a plausible limit.
QTY_TAMPERS = (-5, 0, 100_000)

# Redact anything that looks like a bearer token / JWT / long hex secret.
_SECRET_RE = re.compile(
    r"(?i)(bearer\s+[A-Za-z0-9._\-]+|eyJ[A-Za-z0-9._\-]{8,}|[A-Fa-f0-9]{32,})"
)


# --------------------------------------------------------------------------
# small pure helpers (easy to reason over / unit-test)
# --------------------------------------------------------------------------
def _tokens(key: str) -> list:
    """Split a field name into lower-case word tokens, handling camelCase."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key))
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def _name_matches(key: str, names) -> bool:
    kl = str(key).lower()
    toks = set(_tokens(key))
    return any(kl == n or n in toks for n in names)


def _hint_in(text: str, hints) -> bool:
    low = (text or "").lower()
    return any(h in low for h in hints)


def _redact(text, limit: int = 160) -> str:
    if text is None:
        return ""
    cleaned = _SECRET_RE.sub("[redacted]", str(text))
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:limit]


def _method(ep: dict) -> str:
    return str((ep or {}).get("method") or "GET").upper()


def _sample_body(ep: dict):
    """Pull a sample request body (dict) from an endpoint descriptor, if any."""
    for key in ("body", "json", "params", "data", "sample", "fields", "payload"):
        value = (ep or {}).get(key)
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str):
            s = value.strip()
            if s.startswith("{") or s.startswith("["):
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, dict):
                        return parsed
                except ValueError:
                    pass
    return None


def _status(resp) -> int:
    return int(getattr(resp, "status", 0) or 0)


def _as_json(resp):
    if resp is None:
        return None
    body = getattr(resp, "body", "") or ""
    s = body.strip()
    if not (s.startswith("{") or s.startswith("[")):
        return None
    try:
        return json.loads(s)
    except ValueError:
        return None


def _num(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _num_eq(a, b) -> bool:
    na, nb = _num(a), _num(b)
    if na is not None and nb is not None:
        return abs(na - nb) < 1e-9
    return a == b


def _numeric_leaves(obj, out=None):
    if out is None:
        out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, bool):
                continue
            if isinstance(v, (int, float)):
                out.append((str(k).lower(), v))
            else:
                _numeric_leaves(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _numeric_leaves(v, out)
    return out


def _money_leaves(data):
    return [(k, v) for k, v in _numeric_leaves(data) if _name_matches(k, MONEY_FIELDS)]


def _pick_total(data):
    """Choose the most 'total-like' money leaf for evidence, else the first one."""
    leaves = _money_leaves(data)
    if not leaves:
        return None
    preferred = ("total", "grand_total", "grandtotal", "amount", "payable", "charge")
    for name in preferred:
        for k, v in leaves:
            if k == name or name in _tokens(k):
                return (k, v)
    return leaves[0]


def _ok(resp) -> bool:
    """2xx with no obvious error/limit token in the body (diff, not status-only)."""
    if resp is None or not (200 <= _status(resp) < 300):
        return False
    body = (getattr(resp, "body", "") or "").lower()
    bad = ("already", "limit", "exhaust", "exceeded", "denied", "insufficient",
           "duplicate", "conflict", "not allowed", "forbidden", "invalid",
           "error", "cannot", "rejected", "too many")
    return not any(token in body for token in bad)


def _reflects_amount(data, value):
    """True when the server echoed/stored the exact tampered amount."""
    if data is None:
        return False, None
    for k, v in _money_leaves(data):
        if _num_eq(v, value):
            return True, (k, v)
    for k, v in _numeric_leaves(data):   # fall back to any echoed numeric field
        if _num_eq(v, value):
            return True, (k, v)
    return False, None


def _has_credit(data):
    """True when a money leaf went negative (store credit) or a credit appeared."""
    if data is None:
        return False, None
    total = _pick_total(data)
    if total is not None and _num(total[1]) is not None and _num(total[1]) < 0:
        return True, total
    for k, v in _money_leaves(data):
        if _num(v) is not None and _num(v) < 0:
            return True, (k, v)
    for k, v in _numeric_leaves(data):
        if _name_matches(k, ("credit", "refund", "cashback")) and (_num(v) or 0) > 0:
            return True, (k, v)
    return False, None


def _find_key(data, key):
    """Recursively find the first value for a (lower-cased) key."""
    if isinstance(data, dict):
        for k, v in data.items():
            if str(k).lower() == key:
                return v
        for v in data.values():
            got = _find_key(v, key)
            if got is not None:
                return got
    elif isinstance(data, list):
        for v in data:
            got = _find_key(v, key)
            if got is not None:
                return got
    return None


def _role_reflected(data):
    """True when the response shows an injected privilege took effect."""
    if not isinstance(data, (dict, list)):
        return False, None
    for k, want in (("role", "admin"), ("account_type", "admin"),
                    ("privilege", "admin")):
        v = _find_key(data, k)
        if isinstance(v, str) and v.lower() == want:
            return True, (k, v)
    for k in ("is_admin", "is_staff", "is_verified", "verified", "admin"):
        if _find_key(data, k) is True:
            return True, (k, True)
    return False, None


def _parallel_burst(fetch, method, url, headers, body, n):
    """Fire ``n`` identical requests that all release at the same instant.

    Concurrency pattern adapted from ``tools/h1_race.py`` (threading.Barrier so
    every worker starts together); each request still goes through the injected
    ``fetch`` so the burst is SSRF-safe and mockable.  Returns a list of
    ``(index, resp_or_None, error_or_None)``.
    """
    results = []
    lock = threading.Lock()
    barrier = threading.Barrier(n)

    def worker(i):
        try:
            barrier.wait(timeout=10)
        except threading.BrokenBarrierError:
            pass
        try:
            resp = fetch(method, url, headers=dict(headers or {}), body=body)
        except Exception as exc:  # a dead host must never abort the run
            with lock:
                results.append((i, None, repr(exc)[:80]))
            return
        with lock:
            results.append((i, resp, None))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    return results


# --------------------------------------------------------------------------
# the kit
# --------------------------------------------------------------------------
class LogicRaceKit:
    """Depth kit for business-logic abuse and race conditions."""

    name = "logic-race"
    classes = ("business-logic", "race-condition")

    # -- selection ---------------------------------------------------------
    def applicable(self, ctx: HuntContext) -> bool:
        for ep in ctx.endpoints or []:
            if _method(ep) in ("POST", "PUT", "PATCH"):
                return True
        return _hint_in(self._surface_text(ctx),
                        RACE_HINTS + ("cart", "checkout", "coupon", "order",
                                      "workflow", "wizard", "step", "discount",
                                      "payment", "price"))

    # -- drive -------------------------------------------------------------
    def run(self, ctx: HuntContext) -> list:
        findings = []
        write = bool(ctx.allow_write)
        fetch = ctx.fetch if callable(ctx.fetch) else None
        seen_race = set()

        for ep in ctx.endpoints or []:
            method = _method(ep)
            url = str((ep or {}).get("url") or "")
            if not url:
                continue

            race_ep = False
            if method in ("POST", "PUT") and self._is_race_candidate(ep, url):
                key = (method, url.split("?")[0])
                if key not in seen_race:
                    seen_race.add(key)
                    findings += self._race(ctx, method, url, _sample_body(ep) or {},
                                           write, fetch)
                race_ep = True  # single-use budget: no sequential coupon replay here

            if method not in ("POST", "PUT", "PATCH"):
                continue
            body = _sample_body(ep)
            if body is None:
                continue

            findings += self._price_tamper(ctx, method, url, body, write, fetch)
            findings += self._qty_tamper(ctx, method, url, body, write, fetch)
            findings += self._currency_swap(ctx, method, url, body, write, fetch)
            if not race_ep:
                findings += self._coupon_abuse(ctx, method, url, body, write, fetch)
            findings += self._role_injection(ctx, method, url, body, write, fetch)

        findings += self._step_skip(ctx, write, fetch)
        return findings

    # -- business logic: price -------------------------------------------
    def _price_tamper(self, ctx, method, url, body, write, fetch):
        fields = [k for k in body if _name_matches(k, MONEY_FIELDS)]
        if not fields:
            return []
        if not write or fetch is None:
            return [self._hypothesis(
                "business-logic", "price", "price-tamper", method, url, "high",
                f"Price/amount tampering on {method} {self._path(url)}",
                ("Resend with the money field(s) set to 1, 0, a negative value, "
                 "a huge value and a 64-bit overflow; a server that trusts the "
                 "client amount lets you pay an attacker-chosen total."),
                fields=fields,
                extra={"money_fields": fields, "tamper_values": list(MONEY_TAMPERS)},
                chain=["Feed the tampered order into the checkout/pay step",
                       "Combine with coupon-stack for a negative payable"])]

        out = []
        for field in fields:
            original = body.get(field)
            confirmed = None
            for val in MONEY_TAMPERS:
                tampered = dict(body)
                tampered[field] = val
                resp = self._send(ctx, fetch, method, url, tampered)
                data = _as_json(resp)
                ok = _ok(resp)
                reflected, observed = _reflects_amount(data, val)
                reverted = self._revert(ctx, fetch, method, url, body, resp)
                if ok and reflected:
                    confirmed = (val, observed, resp, reverted, original)
                    break
                total = _pick_total(data)
                if total is not None and _num_eq(total[1], original):
                    ctx.notes.append(
                        f"[logic-race] {self._path(url)} recomputes '{field}' "
                        f"server-side (sent {val}, total still {total[1]}); "
                        "price tamper held")
                    break
            if confirmed:
                val, observed, resp, reverted, original = confirmed
                out.append(self._finding(
                    "business-logic", "price", "price-tamper", "high",
                    "confirmed", V_CONFIRMED, method, url,
                    f"Client-supplied price accepted on {method} {self._path(url)}",
                    {"tampered_field": field, "tampered_value": val,
                     "expected": original,
                     "observed": {observed[0]: observed[1]} if observed else None,
                     "status": _status(resp),
                     "snippet": _redact(getattr(resp, "body", "")),
                     "reverted": reverted},
                    [f"Authenticate as a normal user.",
                     f"Send {method} {url} with '{field}' = {val} (was {original}).",
                     f"Server stored/echoed the tampered amount ({observed}).",
                     "Complete the purchase to pay the attacker-chosen total."],
                    [], ["Feed the tampered order into checkout/pay to realise loss"]))
        return out

    # -- business logic: quantity ----------------------------------------
    def _qty_tamper(self, ctx, method, url, body, write, fetch):
        fields = [k for k in body if _name_matches(k, QTY_FIELDS)]
        if not fields:
            return []
        if not write or fetch is None:
            return [self._hypothesis(
                "business-logic", "quantity", "quantity-tamper", method, url,
                "high", f"Quantity tampering on {method} {self._path(url)}",
                ("Resend with the quantity set negative (expect a negative total "
                 "or store credit), zero, and far beyond any stated limit; "
                 "negative quantities that credit the account are the headline."),
                fields=fields,
                extra={"quantity_fields": fields, "tamper_values": list(QTY_TAMPERS)},
                chain=["Pair a negative-quantity credit with a withdrawal/payout"])]

        out = []
        for field in fields:
            original = body.get(field)
            hit = None
            for val in QTY_TAMPERS:
                tampered = dict(body)
                tampered[field] = val
                resp = self._send(ctx, fetch, method, url, tampered)
                data = _as_json(resp)
                ok = _ok(resp)
                reverted = self._revert(ctx, fetch, method, url, body, resp)
                if not ok:
                    continue
                credit, observed = _has_credit(data)
                echoed_neg = (data is not None
                              and _num_eq(_find_key(data, field.lower()), val)
                              and (_num(val) or 0) < 0)
                if (_num(val) or 0) < 0 and (credit or echoed_neg):
                    hit = ("quantity-negative-credit", val,
                           observed or (field, val), resp, reverted,
                           "Negative quantity accepted -> negative total / credit")
                    break
                if (_num(val) or 0) > 1000 and _num_eq(_find_key(data, field.lower()), val):
                    hit = ("quantity-limit-bypass", val, (field, val), resp,
                           reverted, "Quantity far beyond a plausible limit accepted")
                    break
            if hit:
                technique, val, observed, resp, reverted, headline = hit
                sev = "high" if technique == "quantity-negative-credit" else "medium"
                out.append(self._finding(
                    "business-logic", "quantity", technique, sev, "confirmed",
                    V_CONFIRMED, method, url,
                    f"{headline} on {method} {self._path(url)}",
                    {"tampered_field": field, "tampered_value": val,
                     "expected": original,
                     "observed": {observed[0]: observed[1]} if observed else None,
                     "status": _status(resp),
                     "snippet": _redact(getattr(resp, "body", "")),
                     "reverted": reverted},
                    [f"Send {method} {url} with '{field}' = {val} (was {original}).",
                     f"Server accepted it: {observed}.",
                     "Reason about the resulting balance/stock before relying on it."],
                    [], ["Convert a negative-quantity credit into a withdrawal"]))
        return out

    # -- business logic: currency ----------------------------------------
    def _currency_swap(self, ctx, method, url, body, write, fetch):
        fields = [k for k in body if _name_matches(k, CURRENCY_FIELDS)]
        if not fields:
            return []
        field = fields[0]
        original = str(body.get(field) or "")
        target = next((c for c in ("USD", "EUR", "INR", "JPY", "GBP", "XXX")
                       if c.lower() != original.lower()), "XXX")
        if not write or fetch is None:
            return [self._hypothesis(
                "business-logic", "currency", "currency-swap", method, url,
                "medium", f"Currency swap on {method} {self._path(url)}",
                (f"Resend with '{field}' changed from {original or 'the default'} "
                 f"to a weaker-unit currency (e.g. {target}) while keeping the "
                 "numeric amount; if the server charges the number without "
                 "converting, you pay far less."),
                fields=fields, extra={"from": original, "to": target})]

        tampered = dict(body)
        tampered[field] = target
        resp = self._send(ctx, fetch, method, url, tampered)
        data = _as_json(resp)
        reverted = self._revert(ctx, fetch, method, url, body, resp)
        cur = _find_key(data, field.lower()) if data else None
        if _ok(resp) and isinstance(cur, str) and cur.lower() == target.lower():
            total = _pick_total(data)
            return [self._finding(
                "business-logic", "currency", "currency-swap", "medium", "firm",
                V_POSSIBLE, method, url,
                f"Currency accepted from client on {method} {self._path(url)}",
                {"tampered_field": field, "from": original, "to": target,
                 "observed_total": (total[1] if total else None),
                 "status": _status(resp),
                 "snippet": _redact(getattr(resp, "body", "")),
                 "reverted": reverted},
                [f"Send {method} {url} with '{field}' = {target} (was {original}).",
                 "Server accepted the swapped currency.",
                 "Confirm the payable was NOT converted (compare in base currency)."],
                ["verify the amount was not converted to the new currency"],
                ["Combine with price-tamper to minimise the payable"])]
        return []

    # -- business logic: coupon reuse / stacking -------------------------
    def _coupon_abuse(self, ctx, method, url, body, write, fetch):
        fields = [k for k in body if _name_matches(k, COUPON_FIELDS)]
        if not fields:
            return []
        field = fields[0]
        code = body.get(field)
        if not write or fetch is None:
            return [self._hypothesis(
                "business-logic", "coupon", "coupon-reuse-stack", method, url,
                "medium", f"Coupon reuse/stacking on {method} {self._path(url)}",
                (f"Apply '{field}'={code} twice in sequence (reuse) and apply two "
                 "different codes together (stacking); a single-use or "
                 "non-stackable discount that applies more than once is a bug."),
                fields=fields)]

        r1 = self._send(ctx, fetch, method, url, dict(body))
        r2 = self._send(ctx, fetch, method, url, dict(body))
        reverted = self._revert(ctx, fetch, method, url, body, r2)
        if _ok(r1) and _ok(r2):
            t1, t2 = _pick_total(_as_json(r1)), _pick_total(_as_json(r2))
            return [self._finding(
                "business-logic", "coupon", "coupon-reuse", "medium", "firm",
                V_POSSIBLE, method, url,
                f"Coupon '{field}' accepted twice on {method} {self._path(url)}",
                {"tampered_field": field, "code": _redact(code, 40),
                 "first_total": (t1[1] if t1 else None),
                 "second_total": (t2[1] if t2 else None),
                 "statuses": [_status(r1), _status(r2)], "reverted": reverted},
                [f"Apply coupon '{field}' once via {method} {url}.",
                 "Apply the same coupon again; it was accepted a second time.",
                 "Confirm the discount compounded / the coupon is single-use."],
                ["confirm the coupon is single-use and the discount compounded"],
                ["Stack with price-tamper for a negative payable"])]
        return []

    # -- business logic: ownership / role injection ----------------------
    def _role_injection(self, ctx, method, url, body, write, fetch):
        account_ish = (_hint_in(self._path(url), ACCOUNT_HINTS)
                       or any(_name_matches(k, IDENTITY_FIELDS) for k in body))
        if not account_ish:
            return []
        if not write or fetch is None:
            return [self._hypothesis(
                "business-logic", "role", "role-field-injection", method, url,
                "high", f"Ownership/role field injection on {method} {self._path(url)}",
                ("Add privilege fields the UI never sends - role=admin, "
                 "is_admin=true, is_verified=true, account_type=admin - to the "
                 "request body; mass-assignment may bind them and elevate you."),
                extra={"injected": list(ROLE_INJECT.keys())},
                chain=["Use the elevated role against admin-only endpoints (BFLA)"])]

        tampered = dict(body)
        tampered.update(ROLE_INJECT)
        resp = self._send(ctx, fetch, method, url, tampered)
        data = _as_json(resp)
        elevated, observed = _role_reflected(data)
        reverted = self._revert(ctx, fetch, method, url, body, resp)
        if _ok(resp) and elevated:
            return [self._finding(
                "business-logic", "role", "role-field-injection", "high",
                "confirmed", V_CONFIRMED, method, url,
                f"Mass-assignment: privilege field bound on {method} {self._path(url)}",
                {"injected": list(ROLE_INJECT.keys()),
                 "reflected": {observed[0]: observed[1]} if observed else None,
                 "status": _status(resp),
                 "snippet": _redact(getattr(resp, "body", "")),
                 "reverted": reverted},
                [f"Send {method} {url} with the normal body plus "
                 f"{json.dumps(ROLE_INJECT)}.",
                 f"Response shows the elevated field took effect ({observed}).",
                 "Re-read the profile to confirm the privilege persisted."],
                [], ["Use the elevated role to reach admin-only endpoints (BFLA)"])]
        return []

    # -- business logic: step-skip / forced browsing ---------------------
    def _step_skip(self, ctx, write, fetch):
        groups = {}
        for ep in ctx.endpoints or []:
            if _method(ep) not in ("POST", "PUT"):
                continue
            url = str((ep or {}).get("url") or "")
            flow = (ep or {}).get("workflow") or (ep or {}).get("flow")
            if not flow:
                m = WORKFLOW_PATH_RE.search(url)
                flow = m.group(1).lower() if m else None
            if not flow:
                continue
            step = (ep or {}).get("step")
            if step is None:
                m = re.search(r"step[-_/]?(\d+)", url.lower())
                step = int(m.group(1)) if m else (
                    999 if _hint_in(url, FINAL_STEP_WORDS) else 0)
            groups.setdefault(str(flow), []).append((int(step), ep, url))

        out = []
        for flow, items in groups.items():
            if len(items) < 2:
                continue
            items.sort(key=lambda t: t[0])
            _, final_ep, final_url = items[-1]
            prereq = self._path(items[0][2])
            method = _method(final_ep)
            if not write or fetch is None:
                out.append(self._hypothesis(
                    "business-logic", "workflow", "step-skip-forced-browse",
                    method, final_url, "high",
                    f"Workflow step-skip on {method} {self._path(final_url)}",
                    (f"Call the final step '{self._path(final_url)}' directly "
                     f"without completing the prerequisite '{prereq}'; a server "
                     "that does not check prior-state lets you forced-browse past "
                     "payment/verification."),
                    extra={"flow": flow, "prerequisite": prereq,
                           "final_step": self._path(final_url)}))
                continue
            body = _sample_body(final_ep) or {}
            resp = self._send(ctx, fetch, method, final_url, body)
            if _ok(resp):
                reverted = self._revert(ctx, fetch, method, final_url, body, resp)
                out.append(self._finding(
                    "business-logic", "workflow", "step-skip-forced-browse",
                    "high", "confirmed", V_CONFIRMED, method, final_url,
                    f"Workflow final step reachable without prerequisite "
                    f"on {method} {self._path(final_url)}",
                    {"flow": flow, "prerequisite_skipped": prereq,
                     "status": _status(resp),
                     "snippet": _redact(getattr(resp, "body", "")),
                     "reverted": reverted},
                    [f"Do NOT perform the prerequisite step '{prereq}'.",
                     f"Call {method} {final_url} directly.",
                     "The final step completed without its precondition."],
                    [], ["Skip payment/verification to obtain goods or access"]))
        return out

    # -- race conditions --------------------------------------------------
    def _race(self, ctx, method, url, body, write, fetch):
        action = self._path(url)
        if not write or fetch is None:
            return [self._hypothesis(
                "race-condition", "double-spend", "parallel-submit-double-spend",
                method, url, "high",
                f"Possible race (double-spend / limit-bypass) on {method} {action}",
                (f"Single-use/limited action. Fire ~{SAFE_BURST} identical "
                 f"{method} {action} requests in parallel (same body and auth), "
                 "released simultaneously; if more than one succeeds the "
                 "check-then-act window is exploitable (double redeem / "
                 "over-withdraw / multi-vote)."),
                extra={"suggested_burst": SAFE_BURST, "expected_successes": 1},
                chain=["Amplify with price/quantity tamper for a larger loss"])]

        host = urlsplit(url).hostname or ""
        if host and not ctx.in_scope(host):
            return []
        results = _parallel_burst(fetch, method, url, self._auth(ctx), body, SAFE_BURST)
        statuses = sorted(_status(r) for _, r, _ in results if r is not None)
        successes = [r for _, r, _ in results if _ok(r)]
        n_ok = len(successes)
        if n_ok > 1:
            return [self._finding(
                "race-condition", "double-spend", "parallel-submit-double-spend",
                "high", "confirmed", V_CONFIRMED, method, url,
                f"Race condition: {n_ok}/{SAFE_BURST} parallel {method} {action} "
                "succeeded (single-use action, expected 1)",
                {"burst": SAFE_BURST, "expected_successes": 1,
                 "observed_successes": n_ok, "statuses": statuses,
                 "snippet": _redact(getattr(successes[0], "body", "")),
                 "reverted": "manual - reconcile the extra successful actions"},
                [f"Prepare {SAFE_BURST} identical {method} {url} requests.",
                 "Release them simultaneously (shared barrier / single burst).",
                 f"{n_ok} of {SAFE_BURST} returned success though the action is "
                 "single-use."],
                [], ["Pair with price/quantity tamper to amplify the impact"])]
        ctx.notes.append(f"[logic-race] {method} {action}: race burst held "
                         f"({n_ok}/{SAFE_BURST} ok, statuses={statuses})")
        return []

    # -- shared machinery -------------------------------------------------
    def _is_race_candidate(self, ep, url) -> bool:
        tags = " ".join(str((ep or {}).get(k) or "")
                        for k in ("name", "tag", "tags", "type", "action"))
        return _hint_in(url, RACE_HINTS) or _hint_in(tags, RACE_HINTS)

    def _surface_text(self, ctx) -> str:
        bits = []
        for ep in ctx.endpoints or []:
            bits.append(str((ep or {}).get("url") or ""))
            for k in ("name", "tag", "tags", "workflow", "flow", "type", "action"):
                v = (ep or {}).get(k)
                if v:
                    bits.append(str(v))
        tech = ctx.tech or {}
        if isinstance(tech, dict):
            bits.extend(str(x) for x in tech.keys())
            bits.extend(str(x) for x in tech.values())
        return " ".join(bits).lower()

    def _auth(self, ctx) -> dict:
        return dict(getattr(ctx.account_a, "headers", {}) or {})

    def _send(self, ctx, fetch, method, url, body, headers=None):
        """One state-changing request through ctx.fetch, with scope + auth."""
        if fetch is None:
            return None
        host = urlsplit(url).hostname or ""
        if host and not ctx.in_scope(host):
            return None
        hdrs = dict(headers or {})
        for k, v in self._auth(ctx).items():
            hdrs.setdefault(k, v)
        try:
            return fetch(method, url, headers=hdrs, body=body)
        except Exception:
            return None

    def _created_id(self, data):
        if not isinstance(data, dict):
            return None
        for k in ("id", "order_id", "orderId", "uuid", "ref", "reference",
                  "line_id", "lineId", "resource_id", "cart_id"):
            if k in data and isinstance(data[k], (str, int)) and not isinstance(data[k], bool):
                return str(data[k])
        for v in data.values():
            if isinstance(v, dict):
                got = self._created_id(v)
                if got:
                    return got
        return None

    def _revert(self, ctx, fetch, method, url, original_body, resp):
        """Best-effort auto-revert of the write we just made.

        PUT/PATCH restores the original body; a POST that created an object is
        removed with DELETE (only ever on the object this kit created).  Returns
        True on a clean revert, "manual" when nothing could be auto-undone, or
        False on error.
        """
        try:
            if method in ("PUT", "PATCH"):
                r = self._send(ctx, fetch, method, url, original_body)
                return bool(r is not None and 200 <= _status(r) < 400)
            if method == "POST":
                oid = self._created_id(_as_json(resp))
                if oid:
                    base = url.split("?")[0].rstrip("/")
                    r = self._send(ctx, fetch, "DELETE", f"{base}/{oid}", None)
                    return bool(r is not None and _status(r) in (200, 202, 204, 404))
                return "manual"
        except Exception:
            return False
        return "manual"

    @staticmethod
    def _path(url: str) -> str:
        try:
            parsed = urlsplit(url)
            return parsed.path or url
        except Exception:
            return url

    # -- finding builders -------------------------------------------------
    def _hypothesis(self, cls, axis, technique, method, url, severity, title,
                    detail, fields=None, extra=None, chain=None):
        evidence = {"mode": "hypothesis (dry-run; ctx.allow_write is False)",
                    "manual_test": detail}
        if fields:
            evidence["fields"] = list(fields)
        if extra:
            evidence.update(extra)
        return Finding(
            cls=cls, title=title, severity=severity, confidence="tentative",
            axis=axis, technique=technique, method=method, url=url,
            evidence=evidence, verdict=V_POSSIBLE, repro=[detail],
            kill_reasons=["requires ctx.allow_write to execute and confirm "
                          "(hypothesis only; no request was sent)"],
            chain_hints=list(chain or []))

    def _finding(self, cls, axis, technique, severity, confidence, verdict,
                 method, url, title, evidence, repro, kill_reasons, chain):
        return Finding(
            cls=cls, title=title, severity=severity, confidence=confidence,
            axis=axis, technique=technique, method=method, url=url,
            evidence=evidence, verdict=verdict, repro=list(repro),
            kill_reasons=list(kill_reasons), chain_hints=list(chain))


register(LogicRaceKit())
