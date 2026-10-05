"""Access-control depth kit — IDOR / BOLA / BFLA (broken object- and
function-level authorisation).

This is a depth kit for the Hunter Engine. It does not re-implement detection
logic that already lives in the repo; it *drives* the existing tools:

  * ``tools.two_account_idor.test_endpoint`` — the canonical A-vs-B-vs-anon
    cross-account read classifier (with its PUBLIC false-positive guard).
  * ``tools.two_account_idor._similar`` / ``._snippet`` — body-diffing and the
    redacted, length-capped excerpt used in evidence.
  * ``tools.chain_engine.sibling_endpoints`` — the Sibling Rule expansion.

It also mirrors the capture -> mutate -> confirm write battery pattern from
``tools.h1_mutation_idor`` for the cross-account tamper axis, but always with a
capture-then-revert guarantee so a detection run never leaves the target
mutated.

Every request goes through ``ctx.fetch`` (injected, SSRF-safe, mockable), so the
whole kit is unit-testable offline against a fake target. Findings never carry
raw auth tokens or full response bodies — only statuses, lengths, a short
redacted snippet, the touched field name and our own benign canary marker.

Axes (all the ways a broken object/function authorisation shows up):
  * read    — cross-account read: replay A's id-bearing request as B and anon.
  * write   — cross-account tamper: PATCH/PUT A's object as B, confirm via an
              owner read, then auto-revert (highest-value axis).
  * bfla    — method-swap on a GET endpoint (PUT/POST/PATCH/DELETE).
  * idmut   — id-variant generation (numeric +/-1, zero-pad, int<->str,
              URL-encoded, base64, body-wrapped, UUID nibble-flip).
  * sibling — expand each URL via the Sibling Rule and test cross-account.

Safety: no state-changing request runs unless ``ctx.allow_write``; writes always
capture-then-revert; a destructive DELETE is never fired at an object the kit did
not create, so DELETE exposure is surfaced non-destructively through an OPTIONS
``Allow`` capability probe instead.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

# --- make the repo root importable so ``tools.*`` resolves however we are run -
_REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from tools import chain_engine, two_account_idor  # noqa: E402
from tools.hunter.contract import (  # noqa: E402
    Finding,
    V_CONFIRMED,
    V_POSSIBLE,
    register,
)

# Axis slugs (go into Finding.axis).
AXIS_READ = "read"
AXIS_WRITE = "write"
AXIS_BFLA = "bfla"
AXIS_IDMUT = "idmut"
AXIS_SIBLING = "sibling"

# Statuses that count as the server having *denied* the request.
_DENIED = (401, 403, 404)
# Statuses that count as a state-changing method having been *accepted*.
_ACCEPTED = (200, 201, 202, 204)

# JSON string fields we are willing to tamper (and cleanly restore) for the
# cross-account write axis. Chosen to be benign, human-readable labels rather
# than anything security-relevant.
_WRITABLE_FIELDS = (
    "name", "title", "description", "label", "note", "notes",
    "nickname", "display_name", "bio", "comment", "subject", "message",
)

# A benign, obvious canary written during the write/tamper probe and removed by
# the auto-revert. Never a secret, so it is safe to record in evidence.
_CANARY = "hunter-canary-revertme"

# --- id detection -----------------------------------------------------------
import re  # noqa: E402  (kept local to the id helpers below)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_NUM_RE = re.compile(r"^\d+$")
_HEXISH_RE = re.compile(r"^[0-9a-fA-F]{16,}$")   # long opaque hex id
_ID_KEY_RE = re.compile(
    r"(id|uid|uuid|gid|key|ref|user|account|order|object|record|"
    r"doc|file|item|resource|number|no|pid|oid)",
    re.I,
)

# id-variant technique groups.
_ENCODING_TECHS = {"zero_pad", "url_encoded", "double_url_encoded", "base64"}
_NEIGHBOUR_TECHS = {"numeric_plus1", "numeric_minus1", "uuid_nibble_flip"}


# --- small, dependency-free helpers ----------------------------------------
def _ep_url(ep) -> str:
    if isinstance(ep, dict):
        return str(ep.get("url") or ep.get("endpoint") or "")
    return str(getattr(ep, "url", "") or "")


def _ep_method(ep) -> str:
    if isinstance(ep, dict):
        return str(ep.get("method") or "GET").upper()
    return str(getattr(ep, "method", "GET") or "GET").upper()


def _acc_headers(acc) -> dict:
    """A copy of an account's auth headers, or {} for anon / no account."""
    if acc is None:
        return {}
    h = getattr(acc, "headers", None)
    return dict(h) if h else {}


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def _fetch(ctx, url, headers, body=None, method="GET"):
    """One request through the injected, SSRF-safe fetcher. Never raises on a
    dead host — ``ctx.fetch`` returns None, which callers handle."""
    try:
        return ctx.fetch(method, url, headers=headers, body=body)
    except Exception:
        return None


def _is_catchall(ctx, resp) -> bool:
    """True if the SPA baseline says this response is the catch-all shell (so
    it is noise, not a live endpoint / not a finding)."""
    if resp is None:
        return False
    base = getattr(ctx, "baseline", None)
    if base is None:
        return False
    try:
        return bool(base.is_catchall(resp.status, resp.body))
    except Exception:
        return False


def _mk_adapter(ctx, method, body=None):
    """Adapt ``ctx.fetch(method, url, headers, body)`` to the
    ``fetch(url, headers) -> (status, body)`` shape that
    ``two_account_idor.test_endpoint`` expects, so we reuse it verbatim."""
    def fetch(url, headers):
        r = _fetch(ctx, url, headers, body=body, method=method)
        if r is None:
            return (0, "")
        return (r.status, r.body or "")
    return fetch


def _chain_hints(url: str) -> list:
    hints = ["Test PUT/PATCH/DELETE on the same path for write-side BOLA/BFLA."]
    try:
        sibs = chain_engine.sibling_endpoints(url)
    except Exception:
        sibs = []
    hints += [f"Sibling endpoint worth testing cross-account: {s}" for s in sibs[:6]]
    return hints


# --- id location + mutation -------------------------------------------------
def _locate_id(url: str):
    """Find the object identifier in ``url``. Returns a descriptor dict (kind
    'path' or 'query') or None. Prefers a query id-param, else the right-most
    numeric / UUID / long-hex path segment."""
    try:
        parts = urlsplit(url)
    except Exception:
        return None

    q = parse_qsl(parts.query, keep_blank_values=True)
    for i, (k, v) in enumerate(q):
        if not v:
            continue
        if _ID_KEY_RE.search(k) or _UUID_RE.match(v) or _HEXISH_RE.match(v):
            return {"kind": "query", "key": k, "index": i, "value": v,
                    "parts": parts, "query": q}

    segs = parts.path.split("/")
    for i in range(len(segs) - 1, -1, -1):
        s = segs[i]
        if s and (_NUM_RE.match(s) or _UUID_RE.match(s) or _HEXISH_RE.match(s)):
            return {"kind": "path", "index": i, "value": s,
                    "segs": segs, "parts": parts}
    return None


def _is_id_bearing(url: str) -> bool:
    return _locate_id(url) is not None


def _sub_id(loc: dict, new_value: str) -> str:
    """Rebuild the URL with the located id replaced by ``new_value``."""
    p = loc["parts"]
    if loc["kind"] == "path":
        segs = list(loc["segs"])
        segs[loc["index"]] = new_value
        return urlunsplit((p.scheme, p.netloc, "/".join(segs), p.query, p.fragment))
    q = list(loc["query"])
    q[loc["index"]] = (loc["key"], new_value)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))


def _flip_uuid_nibble(u: str) -> str:
    """Flip the last hex nibble of a UUID (adjacent, almost-certainly-foreign
    object id) while keeping the dashes."""
    for i in range(len(u) - 1, -1, -1):
        c = u[i]
        if c in "0123456789abcdefABCDEF":
            return u[:i] + format(int(c, 16) ^ 0x1, "x") + u[i + 1:]
    return u


def _id_url_variants(value: str) -> list:
    """(technique, new_id) pairs that substitute into the URL. Encodings of the
    *same* id (zero-pad / URL-encode / base64) probe for a check that can be
    bypassed by encoding; neighbours (+/-1, nibble-flip) probe enumeration."""
    out = []
    if _NUM_RE.match(value):
        n = int(value)
        out.append(("numeric_plus1", str(n + 1)))
        if n - 1 >= 0:
            out.append(("numeric_minus1", str(n - 1)))
        out.append(("zero_pad", value.zfill(len(value) + 3)))
    out.append(("url_encoded", quote(value, safe="")))
    out.append(("double_url_encoded", quote(quote(value, safe=""), safe="")))
    try:
        out.append(("base64", base64.b64encode(value.encode()).decode()))
    except Exception:
        pass
    if _UUID_RE.match(value):
        out.append(("uuid_nibble_flip", _flip_uuid_nibble(value)))

    seen, res = set(), []
    for tech, v in out:
        if not v or v == value or v in seen:
            continue
        seen.add(v)
        res.append((tech, v))
    return res


def _id_body_variants(value: str) -> list:
    """(technique, body) pairs that wrap the id (or a neighbour) in a JSON body,
    for endpoints that read the id from the body rather than the path. int<->str
    and array-wrapping probe type-confusion around the ownership check."""
    out = []
    if _NUM_RE.match(value):
        n = int(value)
        out.append(("body_wrap_int_neighbour", {"id": n + 1}))
        out.append(("body_wrap_str", {"id": str(n)}))
        out.append(("body_wrap_array", {"id": [n]}))
    else:
        out.append(("body_wrap_str", {"id": value}))
        out.append(("body_wrap_array", {"id": [value]}))
    return out


# --- write / tamper machinery (capture -> mutate -> confirm -> revert) -------
def _pick_writable_field(body: str):
    """Return (field, original_value) for a benign, revertible JSON string field,
    or (None, None) when there is nothing safe to tamper."""
    try:
        obj = json.loads(body)
    except Exception:
        return None, None
    if not isinstance(obj, dict):
        return None, None
    for f in _WRITABLE_FIELDS:
        if isinstance(obj.get(f), str):
            return f, obj[f]
    return None, None


def _field_equals(body: str, field: str, value) -> bool:
    try:
        obj = json.loads(body)
    except Exception:
        return False
    return isinstance(obj, dict) and obj.get(field) == value


def _canary_for(orig_val) -> str:
    return _CANARY if orig_val != _CANARY else _CANARY + "-2"


def _cross_write(ctx, url, method, a_h, b_h):
    """Capture A's object, tamper one benign field as B, confirm via an owner
    read, then auto-revert. Returns a result dict (no sensitive values) or None
    when no safe, revertible write could be set up. Mirrors the h1_mutation_idor
    battery but with a hard capture-then-revert guarantee."""
    orig = _fetch(ctx, url, a_h)                 # owner read -> capture
    if orig is None or orig.status != 200 or _is_catchall(ctx, orig):
        return None
    field, orig_val = _pick_writable_field(orig.body or "")
    if field is None:
        return None                              # nothing safe to tamper -> skip
    canary = _canary_for(orig_val)

    w = _fetch(ctx, url, b_h, body={field: canary}, method=method)   # tamper as B
    if w is None:
        return None
    accepted = w.status in _ACCEPTED

    after = _fetch(ctx, url, a_h)                 # confirm via owner read
    changed = (after is not None and after.status == 200
               and _field_equals(after.body or "", field, canary))

    reverted = False
    if changed:
        _fetch(ctx, url, b_h, body={field: orig_val}, method=method)   # revert as B
        back = _fetch(ctx, url, a_h)
        reverted = (back is not None and back.status == 200
                    and _field_equals(back.body or "", field, orig_val))
        if not reverted:
            # Belt and braces: restore as the owner too.
            _fetch(ctx, url, a_h, body={field: orig_val}, method=method)
            back2 = _fetch(ctx, url, a_h)
            reverted = (back2 is not None
                        and _field_equals(back2.body or "", field, orig_val))

    return {
        "accepted": accepted,
        "changed": changed,
        "reverted": reverted,
        "owner_read_status": orig.status,
        "write_status": w.status,
        "confirm_status": (after.status if after else None),
        "field": field,
        "canary": canary,
    }


def _parse_allow(resp) -> set:
    """Methods advertised by an OPTIONS response (``Allow`` and the CORS
    ``Access-Control-Allow-Methods`` header)."""
    out = set()
    if resp is None:
        return out
    for hk in ("Allow", "Access-Control-Allow-Methods"):
        v = resp.header(hk)
        if v:
            for m in v.split(","):
                m = m.strip().upper()
                if m:
                    out.add(m)
    return out


# --- the axes ---------------------------------------------------------------
def _read_axis(ctx, ep) -> list:
    """Cross-account read: replay A's id-bearing GET as B and anon, classify by
    body-diffing. Reuses ``two_account_idor.test_endpoint`` verbatim (its PUBLIC
    guard vetoes a public resource — not a bug)."""
    url = _ep_url(ep)
    a_h, b_h = _acc_headers(ctx.account_a), _acc_headers(ctx.account_b)

    if getattr(ctx, "baseline", None) is not None:
        if _is_catchall(ctx, _fetch(ctx, url, a_h)):
            return []

    res = two_account_idor.test_endpoint(
        url, "GET", a_h, b_h, fetch=_mk_adapter(ctx, "GET")
    )
    if res.get("verdict") != two_account_idor.POSSIBLE_IDOR:
        return []
    return [Finding(
        cls="idor-bola",
        title="Cross-account read: account B receives account A's object",
        severity="high", confidence="firm", axis=AXIS_READ,
        technique="cross-account-replay", method="GET", url=url,
        verdict=V_POSSIBLE,
        evidence={
            "status_a": res["status_a"], "status_b": res["status_b"],
            "status_anon": res["status_anon"],
            "len_a": res["body_len_a"], "len_b": res["body_len_b"],
            "snippet": res.get("snippet", ""),
        },
        repro=[
            f"GET {url} with account A -> 200 (A's own object).",
            f"Replay GET {url} with account B's auth -> 200 with the same body.",
            f"GET {url} with no auth -> denied (public-resource guard passed).",
        ],
        chain_hints=_chain_hints(url),
    )]


def _idmut_axis(ctx, ep) -> list:
    """ID-mutation: encoding-bypass of the ownership check (as B) and horizontal
    enumeration of neighbouring objects (as A), across URL and body variants."""
    url = _ep_url(ep)
    loc = _locate_id(url)
    if not loc:
        return []
    a_h, b_h = _acc_headers(ctx.account_a), _acc_headers(ctx.account_b)

    base = _fetch(ctx, url, a_h)
    if base is None or base.status != 200 or _is_catchall(ctx, base):
        return []
    base_body = base.body or ""
    findings = []

    # (1) Encoding-bypass, as B: B is denied the plain id, but an *encoded* form
    #     of the SAME id returns A's object (and anon does not -> not public).
    if b_h:
        b_plain = _fetch(ctx, url, b_h)
        if b_plain is not None and b_plain.status in _DENIED:
            hits = []
            for tech, new_id in _id_url_variants(loc["value"]):
                if tech not in _ENCODING_TECHS:
                    continue
                vu = _sub_id(loc, new_id)
                r = _fetch(ctx, vu, b_h)
                if (r is not None and r.status == 200 and not _is_catchall(ctx, r)
                        and two_account_idor._similar(base_body, r.body or "")):
                    ra = _fetch(ctx, vu, {})
                    public = (ra is not None and ra.status == 200
                              and two_account_idor._similar(base_body, ra.body or ""))
                    if not public:
                        hits.append(tech)
            if hits:
                findings.append(Finding(
                    cls="idor-bola",
                    title="Ownership check bypassed by id encoding (cross-account read)",
                    severity="high", confidence="firm", axis=AXIS_IDMUT,
                    technique="+".join(hits), method="GET", url=url,
                    verdict=V_POSSIBLE,
                    evidence={"status_b_plain": b_plain.status,
                              "techniques": hits,
                              "snippet": two_account_idor._snippet(base_body)},
                    repro=[
                        f"GET {url} with account B -> {b_plain.status} (denied).",
                        "GET an encoded form of the same id with account B "
                        "-> 200 with A's object (check bypassed).",
                    ],
                    chain_hints=_chain_hints(url),
                ))

    # (2) Horizontal enumeration, as A: a neighbour id returns a *different*,
    #     non-public, real object through the same endpoint (no object scoping).
    hits = []
    for tech, new_id in _id_url_variants(loc["value"]):
        if tech not in _NEIGHBOUR_TECHS:
            continue
        r = _fetch(ctx, _sub_id(loc, new_id), a_h)
        if r is None or r.status != 200 or _is_catchall(ctx, r):
            continue
        vbody = r.body or ""
        if not vbody or two_account_idor._similar(base_body, vbody):
            continue
        ra = _fetch(ctx, _sub_id(loc, new_id), {})
        if (ra is not None and ra.status == 200
                and two_account_idor._similar(vbody, ra.body or "")):
            continue                              # public neighbour -> not a bug
        hits.append(tech)
    # body-wrapped neighbour (endpoints that read the id from the body).
    for tech, bodyv in _id_body_variants(loc["value"]):
        if "neighbour" not in tech and "array" not in tech:
            continue
        r = _fetch(ctx, url, a_h, body=bodyv)
        if r is None or r.status != 200 or _is_catchall(ctx, r):
            continue
        vbody = r.body or ""
        if vbody and not two_account_idor._similar(base_body, vbody):
            hits.append(tech)
    if hits:
        findings.append(Finding(
            cls="idor-bola",
            title="Horizontal id enumeration returns other objects",
            severity="medium", confidence="tentative", axis=AXIS_IDMUT,
            technique="+".join(hits), method="GET", url=url, verdict=V_POSSIBLE,
            evidence={"base_status": 200, "techniques": hits},
            repro=[
                f"GET {url} with account A -> 200 (A's object).",
                "Mutate the id (neighbour / body-wrapped) and re-request as A "
                "-> 200 with a different object.",
            ],
            kill_reasons=[
                "Confirm the enumerated object belongs to a different principal "
                "(a neighbouring id could be another of account A's own objects)."
            ],
            chain_hints=_chain_hints(url),
        ))
    return findings


def _sibling_axis(ctx, ep) -> list:
    """Expand the URL via the Sibling Rule and test each sibling cross-account
    (siblings usually share the same broken access-control code path)."""
    url = _ep_url(ep)
    a_h, b_h = _acc_headers(ctx.account_a), _acc_headers(ctx.account_b)
    if not b_h:
        return []
    try:
        sibs = chain_engine.sibling_endpoints(url)
    except Exception:
        sibs = []
    out = []
    adapter = _mk_adapter(ctx, "GET")
    for s in sibs:
        if not ctx.in_scope(_host(s)):
            continue
        if getattr(ctx, "baseline", None) is not None:
            if _is_catchall(ctx, _fetch(ctx, s, a_h)):
                continue
        res = two_account_idor.test_endpoint(s, "GET", a_h, b_h, fetch=adapter)
        if res.get("verdict") != two_account_idor.POSSIBLE_IDOR:
            continue
        out.append(Finding(
            cls="idor-bola",
            title="Cross-account read on a sibling endpoint",
            severity="high", confidence="firm", axis=AXIS_SIBLING,
            technique="sibling-endpoint", method="GET", url=s, verdict=V_POSSIBLE,
            evidence={"parent": url, "status_a": res["status_a"],
                      "status_b": res["status_b"], "status_anon": res["status_anon"],
                      "snippet": res.get("snippet", "")},
            repro=[
                f"Derived sibling of {url}.",
                f"GET {s} with account A -> 200, replay with account B -> same body.",
            ],
            chain_hints=_chain_hints(s),
        ))
    return out


def _bfla_axis(ctx, ep) -> list:
    """BFLA method-swap via a non-destructive OPTIONS ``Allow`` capability probe.
    A state-changing method advertised to a non-owner on an object endpoint is a
    function-level authorisation gap. Revertible methods (PUT/PATCH) are actively
    confirmed elsewhere when ``allow_write`` is set; POST/DELETE are never fired
    (POST may create, DELETE may destroy with no clean revert on a foreign
    object), so they are surfaced from the OPTIONS signal only."""
    url = _ep_url(ep)
    b_h = _acc_headers(ctx.account_b)
    probe_h = b_h or {}
    probe_as = "B" if b_h else "anon"

    opt = _fetch(ctx, url, probe_h, method="OPTIONS")
    allowed = _parse_allow(opt)
    if not allowed:
        return []
    actively_probed = bool(ctx.allow_write) and bool(b_h)

    out = []
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        if m not in allowed:
            continue
        if m in ("PUT", "PATCH") and actively_probed:
            continue                              # the active write step owns these
        out.append(Finding(
            cls="bfla",
            title=f"State-changing method {m} advertised to account "
                  f"{probe_as} on an object endpoint",
            severity="medium", confidence="tentative", axis=AXIS_BFLA,
            technique="options-allow-enumeration", method=m, url=url,
            verdict=V_POSSIBLE,
            evidence={"allow": sorted(allowed), "probe_as": probe_as,
                      "options_status": (opt.status if opt else None)},
            repro=[
                f"OPTIONS {url} as account {probe_as} -> Allow advertises {m}.",
                f"On an owner-scoped object endpoint, {m} should not be exposed "
                "to a non-owner.",
            ],
            kill_reasons=[
                "Advertised via OPTIONS Allow but invocation not confirmed; "
                "destructive methods (POST/DELETE) are not auto-fired for safety."
            ],
            chain_hints=_chain_hints(url),
        ))
    return out


def _active_write_bfla(ctx, ep) -> list:
    """The highest-value axis: cross-account data tamper. Under ``allow_write``,
    PATCH/PUT A's object as B with a benign canary, confirm the change via an
    owner read, then auto-revert. A confirmed data change is a critical write
    BOLA; an accepted method with no confirmed change is a function-level gap."""
    url = _ep_url(ep)
    a_h, b_h = _acc_headers(ctx.account_a), _acc_headers(ctx.account_b)
    if not b_h:
        return []
    out = []
    for method in ("PATCH", "PUT"):
        res = _cross_write(ctx, url, method, a_h, b_h)
        if not res:
            continue
        ev = {k: res[k] for k in (
            "owner_read_status", "write_status", "confirm_status",
            "field", "canary", "changed", "reverted",
        )}
        if res["changed"]:
            out.append(Finding(
                cls="idor-bola",
                title="Cross-account write: account B modified account A's object",
                severity="critical",
                confidence="confirmed" if res["reverted"] else "firm",
                axis=AXIS_WRITE, technique="cross-account-tamper",
                method=method, url=url, verdict=V_CONFIRMED, evidence=ev,
                repro=[
                    f"GET {url} as account A -> capture the original field value.",
                    f"{method} {url} as account B with a benign canary -> accepted.",
                    f"GET {url} as account A -> the field now holds the canary.",
                    f"{method} {url} as account B to restore the original value "
                    f"(reverted={res['reverted']}).",
                ],
                kill_reasons=(
                    [] if res["reverted"]
                    else ["Auto-revert failed: the canary may still be in place "
                          "-- manual cleanup required."]
                ),
                chain_hints=_chain_hints(url),
            ))
        elif res["accepted"]:
            out.append(Finding(
                cls="bfla",
                title=f"Account B's {method} accepted on account A's object",
                severity="high", confidence="firm", axis=AXIS_BFLA,
                technique="method-invocation", method=method, url=url,
                verdict=V_POSSIBLE, evidence=ev,
                repro=[
                    f"{method} {url} as account B -> {res['write_status']} "
                    "(accepted; no confirmed data change).",
                ],
                kill_reasons=[
                    "Method accepted but no field change was confirmed via owner "
                    "read; verify whether the write took effect."
                ],
                chain_hints=_chain_hints(url),
            ))
    return out


# --- the kit ----------------------------------------------------------------
class AccessControlKit:
    """IDOR / BOLA / BFLA depth kit."""

    name = "access-control"
    classes = ("idor-bola", "bfla")

    def applicable(self, ctx) -> bool:
        """Warranted when the surface exposes id-bearing endpoints AND we hold at
        least account A (so we can run anon-vs-A); two accounts enable the full
        cross-account matrix."""
        if ctx is None or getattr(ctx, "fetch", None) is None:
            return False
        has_ids = any(_is_id_bearing(_ep_url(ep)) for ep in (ctx.endpoints or []))
        return has_ids and bool(_acc_headers(ctx.account_a))

    def run(self, ctx) -> list:
        if ctx is None or getattr(ctx, "fetch", None) is None:
            return []
        findings = []
        for ep in (ctx.endpoints or []):
            url = _ep_url(ep)
            if not url or not ctx.in_scope(_host(url)) or not _is_id_bearing(url):
                continue
            findings += _read_axis(ctx, ep)
            findings += _idmut_axis(ctx, ep)
            findings += _sibling_axis(ctx, ep)
            findings += _bfla_axis(ctx, ep)
            if ctx.allow_write:
                findings += _active_write_bfla(ctx, ep)

        # Dedupe on the axis-distinguishing key (one finding per real signal).
        seen, out = set(), []
        for f in findings:
            key = (f.cls, f.axis, f.method, f.url, f.technique)
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out


# Self-register at import time (the engine discovers kits by scanning this dir).
register(AccessControlKit())
