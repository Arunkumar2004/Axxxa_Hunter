# BFLA — Broken Function-Level Authorisation (bfla)

Reaching a function or operation your role should not be able to call (admin
actions, other-tenant operations, state-changing verbs). Where BOLA is about a
specific object, BFLA is about the capability itself.

## Checklist
- Map the role matrix: enumerate every function as the HIGH-priv account (admin/manager), recording method+path+body, then replay each as the LOW-priv account and diff.
- Harvest admin/privileged routes from JS bundles, OpenAPI/Swagger, sitemaps and `/api-docs`; client-gated buttons usually name the endpoint even when hidden.
- Sibling-route rule: if `GET /admin/users` enforces auth, probe the neighbours (`/admin/export`, `/admin/delete`, `/admin/reset`, `/admin/impersonate`) which often miss the middleware.
- Method upgrade: a role allowed to `GET` a resource may be allowed to `POST`/`PUT`/`PATCH`/`DELETE` it because the verb-level check is absent.
- Call the admin function with a low-priv token and confirm the privileged effect actually happened (user created, role changed, record deleted), not merely a 200.
- Mass-assignment to self-escalate: add `role`, `is_admin`, `isAdmin`, `user_priv`, `approved`, `email_verified` to a normal create/update body and check whether the privileged field stuck.
- Tenant/org function crossing: call an org-scoped operation while authenticated to a different org (`/org/{other}/settings`).
- Forced browsing to the admin UI/API directly (`/admin`, `/internal`, `/manage`) rather than through the client that hides it.
- Case and path normalisation on the function path (`/Admin/`, `/admin/./`, `/admin%2f`) to dodge a string-match route guard.
- API version downgrade: an old `/v1` admin handler may predate the role check added in `/v2`.
- Workflow/step function skip: jump straight to a privileged step's endpoint (approve, publish, settle) without the preceding authorisation step.
- GraphQL privileged mutations (`deleteUser`, `setRole`) and admin-only queries — resolver-level auth is frequently missing even when the HTTP layer is guarded.
- Gateway trust headers: try `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, or role hints (`X-User-Role: admin`) the app may honour.
- Re-verify under a freshly minted low-priv token (not a lingering admin session) to prove the capability is granted by role, not by a stale cookie.

## Bypasses
- Sibling-endpoint discovery: guess the unguarded verbs/paths next to a guarded admin action.
- Verb swap (`GET`->`PUT`/`DELETE`) and override headers (`X-HTTP-Method-Override: DELETE`) when the primary verb is blocked.
- Path casing and normalisation (`/ADMIN/`, `..;/admin/`, `%2e%2e` segments) to beat prefix/regex route guards.
- Front-end-only gating: the control is hidden client-side but the API accepts the call — drive the API directly.
- Gateway rewrite headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-*`) that re-route to an internal admin path.
- API version downgrade or a legacy mirror host that never received the authorisation middleware.
- Mass-assignment of a privilege field to turn an ordinary write into a vertical escalation.

## Kill rules
- The privileged action returns 200 but produces no privileged effect when verified from another identity.
- The function is reachable only with an admin token you already hold — you proved nothing beyond your own role.
- The echoed privilege field (`isAdmin:true`) grants no real capability on re-check — cosmetic mass-assignment.
- The endpoint is intentionally public/self-service (signup, public search) — not a privileged function.
- It works with no token at all — that is missing authentication, triage separately.
- Client-side-only control with a server that actually rejects the call (403 on the API) — the gate holds.
- The capability is an expected feature of the role you authenticated as.
