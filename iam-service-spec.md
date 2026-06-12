# Internal IAM & Audit Service — Implementation Spec

## Context & goal

We run internal applications on Cloudflare Workers. Authentication is handled at the
edge by **Cloudflare Access** (Zero Trust). We want to stop reimplementing authorization
and audit logging in every app. Build a single **IAM Worker** that all internal apps call
via **service bindings** through a thin client SDK.

Division of responsibility:

- **Cloudflare Access** → authentication (who you are) + coarse gate (can you reach the app at all). Not in scope to build.
- **IAM Worker** → authorization (AWS-IAM-style RBAC over generic, app-owned scopes), auth logging, domain-event audit ingest, and issuing a request context. This is what we build.
- **Apps** → declare their own authz vocabulary (scope dimensions + action catalog + roles) in code and reconcile it in; generate domain audit events (only they know what changed); call `authenticate()` and `audit()` and nothing else.

This is for **internal use** (tens of users, tens of apps). Do **not** over-engineer.
D1 is the datastore. No Pipelines/Iceberg/Zanzibar/graph models.

## Hard requirements & non-negotiables

1. **Stack:** Cloudflare Workers (TypeScript), `WorkerEntrypoint` RPC, D1. No external auth libs except `jose` for JWT validation. Generate all self-owned string ids as **UUIDv7** (time-sortable).
2. **Provisioning needs Cloudflare API access:** the admin service-token flow calls the Cloudflare Access API, so the Worker holds a scoped Cloudflare API token (_Access: Service Tokens Edit_, and Access policy edit if we automate policy inclusion) plus account id as secrets (`CF_API_TOKEN`, `CF_ACCOUNT_ID`). These are admin-only; never expose to app callers.
3. **Caller app identity: verified where a token exists, self-asserted elsewhere.** Service bindings carry no caller metadata; Cloudflare does not provide one. But on any call that forwards a valid Access JWT (`authenticate()`, `issueCapability()`), the token's verified `aud` identifies the Access application, and the IAM Worker derives the app id from the `ACCESS_APPS` map (see JWT section) — that value, not the SDK-passed one, goes into the auth log and the request context. Only where no valid token exists (`audit()`, `redeemCapability()`, failure-path log rows) is the SDK-passed app id used: a trust-the-internal-network value for **audit labeling only** — it is NOT a security boundary. Do not build per-app secret auth; the security perimeter is Access at the edge. Document this split in code comments. **Principal identity is never app-asserted:** wherever the principal matters for a server-side check (authentication, capability issuance), the IAM Worker resolves it from the forwarded Access credentials itself — it never trusts an app-passed principal id for a permission decision.
4. **`can()` must evaluate locally.** `authenticate()` returns the principal _with_ their resolved permissions in one RPC; `can()` is a pure function over that array. No round-trip per permission check.
   4a. **Scope is generic, flat, and app-owned.** A grant/mapping is scoped to a `(scope_type, scope_value)` pair (both NULL = global). `scope_value` is an **opaque, app-owned string** (a slug or uuid) — Propustka never FKs, lists, or interprets it. Dimensions are **flat and independent**: there is no hierarchy or containment between them. An app that needs hierarchy resolves it itself and passes the right scope coordinate on the check. Propustka does **not** own a project list (the `projects` table is gone).
   4b. **App-declared vocabulary, reconciled in.** Each app declares its `AppSchema` — scope dimensions, an action **catalog**, and roles — in its own code, and pushes it via the idempotent `PUT /admin/apps/:app/schema`. Reconcile upserts and prunes `origin='app'` rows and **never** touches `origin='custom'`. The action catalog is the validation source: an action pattern (`*`, exact, or `prefix.*` over a non-empty namespace) is rejected at role/policy/inline-grant creation if it is not allowed by the catalog (`isActionAllowed`).
   4c. **Additive-allow ONLY.** Permissions are AWS-IAM-style but a strict subset: there is **no explicit Deny, no conditions, no ABAC**. A permission either grants (a matching pattern at a satisfying scope) or is silent. Evaluation is a pure union; nothing ever subtracts.
5. **Distinguish 401 from 403.** `authenticate()` returns either a valid principal OR a structured failure reason. Missing/invalid token → 401 (not authenticated). A credential that validates but maps to an unknown or disabled principal → 403 (authenticated, not allowed). A valid principal lacking a permission is `can()` → false → app responds 403. Never collapse these into one exception; the SDK failure object carries the suggested HTTP status.
6. **Audit writes are fire-and-forget.** Use `ctx.waitUntil()`; a failed audit write must never fail or delay the user-facing operation.
7. **Fail-closed.** If policy evaluation cannot complete, deny.
8. **Dev mode.** The SDK must ship a fake implementation (fixed identity, `can()` → true by default) selectable by env flag, so apps run in `wrangler dev` without Access or a running IAM Worker.

## Architecture

```
Browser/Client → Cloudflare Access (edge auth) → App Worker
                                                     │ env.IAM (service binding)
                                                     ▼
                                                 IAM Worker ── D1
```

The app never talks to D1 or validates JWTs itself. All of that lives in the IAM Worker,
reached through the `@firma/iam-client` SDK.

## JWT validation (inside IAM Worker)

- Read the Access app token from the `Cf-Access-Jwt-Assertion` header value (passed in by the SDK).
- Validate with `jose`: `createRemoteJWKSet(new URL(`${TEAM}/cdn-cgi/access/certs`))`, verifying `issuer` (team domain) and `audience`.
- **`audience` is a set, not a single value — and it identifies the calling app.** Each Access application has its own AUD tag, and the IAM Worker serves many apps. Configure the mapping as env (`ACCESS_APPS`, JSON object `{ "<aud-tag>": "<app-id>" }`) and validate the token's `aud` against its keys (`jose` accepts `audience: string[]` — pass `Object.keys(ACCESS_APPS)`). A single-AUD env var would only ever validate tokens for one app.
- **The verified `aud` yields a verified app identity.** On a successfully validated token, resolve `app = ACCESS_APPS[aud]` and use _that_ — not the SDK-passed value — for `auth_log.app` and the request context. App identity on every authenticated call is then cryptographically grounded instead of self-asserted. The SDK-passed `app` is used only where no valid token exists (failure-path log rows, `audit()`, `redeemCapability()` — see hard requirement 3). If the self-asserted `app` differs from the aud-derived one, proceed with the aud-derived value but log the mismatch — it indicates a misconfigured SDK constructor, not an attack.
- **Distinguish "unknown AUD" from a genuinely bad token.** A token that verifies cryptographically but whose `aud` is not a key of `ACCESS_APPS` is an expected misconfiguration: a newly onboarded app whose AUD nobody added to the env. Return `invalid_token` to the caller (apps should not branch on it), but record `reason = 'aud_not_configured'` in `auth_log` and emit an explicit log line — otherwise a forgotten onboarding step looks like a broken login and wastes debugging time.
- JWKS set is cached per-isolate (jose handles this) — this is a reason validation lives in one Worker.
- Identity login → `payload.email` (label) and `payload.sub` (stable external id).
- Service token → `payload.common_name` (= the token Client ID; use as external id). Distinguish by presence of `email` vs `common_name`.
- On any validation failure return a structured failure, not a thrown error.

### Fetching IdP group membership (get-identity)

GitHub org/team (and any IdP group) membership is **not in the app JWT** — the token only
carries a subset of identity due to cookie size limits. To resolve groups for the
group→role mapping, the IAM Worker calls the Access get-identity endpoint:

- `GET ${origin}/cdn-cgi/access/get-identity` with the user's `CF_Authorization` cookie
  forwarded, where **`origin` is the calling app's own origin** (scheme + host of the
  incoming request, passed by the SDK into `authenticate()`).
- **Why the app's origin and not the team domain:** the `CF_Authorization` cookie is
  domain-scoped to the protected app's hostname. Calling
  `<team>.cloudflareaccess.com/cdn-cgi/access/get-identity` with an app-domain cookie
  would not authenticate. The `/cdn-cgi/access/*` path is served by the Access edge layer
  on every protected hostname and never reaches the app Worker, so there is no recursion.
  _(Implementer: verify this server-side fetch against a real Access-protected host early —
  it is the one external integration point in group resolution.)_
- Parse GitHub org/team membership from the returned identity data and normalize each to the
  `<org>/<team>` lowercase `group_ref` form used in `group_role_mappings`.
- **Only for `type='user'` principals.** Skip entirely for service tokens.
- **Cache group membership per principal** with a short TTL (tens of seconds).
  Membership does not change by the second, and get-identity is an extra network call; do not
  call it on every request uncached. This group-membership cache is the only resolution cache —
  there is no separate resolved-principal cache; grants are always read from D1.
- **Group data is login-time, not live.** get-identity returns the identity as Access learned
  it at the user's last IdP authentication / session refresh — GitHub team membership is not
  continuously synced. Removing someone from a GitHub team therefore takes effect only when
  their Access session next refreshes against the IdP (up to the configured session duration),
  not on the next `authenticate()`. For permissions that must be revocable immediately, use
  explicit grants (grant/revoke is effective on the next `authenticate()`, since grants are
  always read from D1) or revoke the user's Access session in the dashboard.
- If get-identity fails, fall back to explicit grants only (do not hard-fail auth) but record
  that group resolution was unavailable — set a `groupsUnavailable: true` flag on the
  `authenticate()` result and write it to the auth log — so a missing-permission denial isn't
  silently caused by a transient identity-endpoint error. Still fail-closed on the _permission_
  decision itself.

## Roles & policies: app-declared in code, reconciled into D1

Role → permission bundles (AWS "managed policies") live **in D1, per app** — the `roles`
table. Each app declares its canonical roles in its own `AppSchema` (`origin='app'`) and
reconciles them in; an admin may compose additional `origin='custom'` policies in the UI.
Roles are no longer a hardcoded code registry — apps disagree on their vocabulary, and a
runtime per-app picker (with real action choices) is now wanted, so the YAGNI deferral was
intentionally resolved.

The **one exception** is a single built-in, cross-app role kept in Worker code:

```ts
// roles.ts — the only built-in. Everything else is per-app DB rows.
export const BUILTIN_ROLES: Record<string, RoleDef> = {
	admin: { name: 'Admin', permissions: ['*'] },
}
```

- `admin = ['*']` must resolve for **any** app, including `app=null` (the cross-app /
  bootstrap path) — so it cannot sit in a per-app DB table. It serves bootstrap admins and
  cross-app (`app=NULL`) grants. An app cannot shadow it (built-ins win on a key collision).
- A `roles` row is a JSON array of action patterns plus an `origin` (`'app'` reconciled from
  code, or `'custom'` admin-composed) — see the data model. Patterns stay as patterns
  (`*`, `prefix.*`, exact); they are not pre-expanded — `permits()` matches them at check time.
- Resolution runs against the `RoleSource` interface (`getRole(app, key)`,
  `listRoles(app)`): the Worker layers the built-ins over the calling app's DB roles, loaded
  once up front so `computePermissions` stays pure (no I/O during the union).
- `grants.role_key` / `group_role_mappings.role_key` are plain TEXT (**no FK** — a grant may
  set `app=NULL` while a `roles` row always has a concrete app, so an FK can't express it).
  Validate the key **at grant/mapping creation time** against the built-ins OR the app's
  `roles` rows (`isKnownRole`); reject unknown keys. A grant whose role key no longer resolves
  confers zero permissions (fail-closed) and is surfaced in the admin UI as dangling.

## Data model (D1)

Two concerns, opposite characteristics: **policies** = mutable current state, read on every
request; **audit** = append-only history, written often, read rarely. Keep them separate.

### Policies

```sql
CREATE TABLE principals (
  id          TEXT PRIMARY KEY,                 -- UUIDv7, ours; STABLE — grants & audit reference this, never external_id
  type        TEXT NOT NULL CHECK (type IN ('user','service')),
  external_id TEXT,                              -- Access `sub` (user) / client_id (service). NULL = user INVITED, not yet claimed (first login pending)
  email       TEXT,                             -- users: invite-match key + label source; NULL for services
  label       TEXT NOT NULL,                     -- email / token name, human-readable
  disabled_at INTEGER,                           -- soft-disable, NULL = active
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- Status is derived: invited (external_id IS NULL) → claimed/active → disabled (disabled_at set).
-- external_id is NULL for invited-not-yet-claimed users, so a plain UNIQUE(type, external_id)
-- would treat those NULLs as distinct. Partial unique indexes (same pattern as grants):
CREATE UNIQUE INDEX idx_principals_uq_external ON principals(type, external_id)
  WHERE external_id IS NOT NULL;
-- At most one user principal per email (the invite target, then the claimed identity):
CREATE UNIQUE INDEX idx_principals_uq_email ON principals(email)
  WHERE type = 'user' AND email IS NOT NULL;

-- ── App-declared vocabulary (reconciled from each app's code) ──────────────────

-- The scope DIMENSIONS an app understands. authenticate() doesn't need this (scope
-- matching is opaque string equality); it exists so the admin UI offers a real dropdown
-- of scope types per app instead of free text. PK (app, scope_type) — a dimension is
-- unique within an app; different apps may reuse the same name.
CREATE TABLE app_scopes (
  app        TEXT NOT NULL,
  scope_type TEXT NOT NULL,                       -- 'organization' | 'team' | 'project' | …
  label      TEXT,                                -- human label for the admin UI
  PRIMARY KEY (app, scope_type)
);

-- The ACTION CATALOG per app — every concrete action the app authorizes against. Roles,
-- custom policies, and inline grants reference these by string (or glob pattern); this is
-- the source of truth the admin UI lists and that isActionAllowed() validates against.
CREATE TABLE app_actions (
  app         TEXT NOT NULL,
  action      TEXT NOT NULL,                      -- concrete action, e.g. 'project.read'
  description TEXT,
  PRIMARY KEY (app, action)
);

-- Named permission BUNDLES (AWS "managed policies"). Either reconciled from app code
-- (origin='app') or composed by an admin in the UI (origin='custom'). `permissions` is a
-- JSON array of action patterns; json_valid keeps malformed JSON out at write time so the
-- read path JSON-parses without defensive guards. PK (app, role_key).
CREATE TABLE roles (
  app         TEXT NOT NULL,
  role_key    TEXT NOT NULL,
  name        TEXT NOT NULL,
  description TEXT,
  permissions TEXT NOT NULL CHECK (json_valid(permissions)),     -- JSON array of action patterns
  origin      TEXT NOT NULL CHECK (origin IN ('app', 'custom')),  -- 'app'=reconciled, 'custom'=admin-made
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (app, role_key)
);

-- ── Grants ─────────────────────────────────────────────────────────────────────

CREATE TABLE grants (
  id           TEXT PRIMARY KEY,                  -- UUIDv7
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  app          TEXT,                              -- NULL = all apps (cross-app, e.g. super-admin)
  role_key     TEXT,                              -- named role/policy; XOR permissions
  permissions  TEXT CHECK (permissions IS NULL OR json_valid(permissions)),  -- inline action set; XOR role_key
  scope_type   TEXT,                              -- NULL = global (all scopes)
  scope_value  TEXT,                              -- OPAQUE, app-owned; NULL = global
  granted_by   TEXT REFERENCES principals(id),
  expires_at   INTEGER,                           -- NULL = permanent
  created_at   INTEGER NOT NULL DEFAULT (unixepoch()),
  CHECK ((role_key IS NULL) <> (permissions IS NULL)),  -- EXACTLY one of role_key / inline permissions
  CHECK ((scope_type IS NULL) = (scope_value IS NULL))  -- scope is both-or-neither
);

-- A grant carries EITHER a named role (a reusable bundle, app-declared or admin-composed)
-- OR an inline JSON action set — exactly one, like an attached managed policy vs. an inline
-- policy (the XOR CHECK). Scope is the generic (scope_type, scope_value) pair; both NULL =
-- global. role_key is NOT FK'd to roles(app, role_key): a grant may set app=NULL (cross-app)
-- while a roles row always has a concrete app, so an FK can't express it — roles are
-- validated in the Worker against the reconciled set.

-- SQLite treats NULLs as distinct in a UNIQUE index, so partial unique indexes; NULL app is
-- folded to '*' so two NULL-app globals still collide. KEY DIFFERENCE vs. roles: the indexes
-- constrain ONLY role-based grants (role_key IS NOT NULL). Inline grants are intentionally
-- unconstrained — each inline permission set is its own distinct attachment (like two
-- separate inline policies), so duplicates across (principal, scope, app) are meaningful.
CREATE UNIQUE INDEX idx_grants_uq_scoped
  ON grants(principal_id, role_key, scope_type, scope_value, COALESCE(app, '*'))
  WHERE role_key IS NOT NULL AND scope_value IS NOT NULL;
CREATE UNIQUE INDEX idx_grants_uq_global
  ON grants(principal_id, role_key, COALESCE(app, '*'))
  WHERE role_key IS NOT NULL AND scope_value IS NULL;

CREATE INDEX idx_grants_principal ON grants(principal_id);
```

**Scope values are app-owned; Propustka no longer keeps a list.** A grant's scope is the
generic `(scope_type, scope_value)` pair — `scope_type` the dimension name an app declared
(`app_scopes`), `scope_value` an opaque slug/uuid the app owns. Propustka never FKs or
interprets it; the app keys its own domain rows by these values. There is **no** `projects`
table (retired) and no `registerProject` RPC — an app that adds a scope dimension declares
it in its `AppSchema` and reconciles, nothing more. Grants are filtered by the aud-verified
calling app at resolution time: a grant counts when its `app` equals the calling app OR is
NULL (cross-app).

### Group → role mappings (IdP group inheritance)

Effective permissions for a **user** principal come from two sources unioned together:
explicit `grants` rows (above) **and** roles derived from their IdP group membership. This lets
us express "anyone in GitHub team `my-org/core-devs` is an editor of project X" as a single row,
without per-person grants. The membership data is **not in the Access JWT** (cookie size limit) —
it is fetched from the Access get-identity endpoint at `authenticate()` time (see above).

```sql
CREATE TABLE group_role_mappings (
  id          TEXT PRIMARY KEY,                  -- UUIDv7
  provider    TEXT NOT NULL,                     -- 'github'
  group_ref   TEXT NOT NULL,                     -- 'my-org/core-devs' (org/team slug, lowercase)
  role_key    TEXT NOT NULL,                     -- validated against the app's reconciled roles
  app         TEXT,                              -- NULL = all apps
  scope_type  TEXT,                              -- NULL = global
  scope_value TEXT,                              -- OPAQUE, app-owned; NULL = global
  created_at  INTEGER NOT NULL DEFAULT (unixepoch()),
  CHECK ((scope_type IS NULL) = (scope_value IS NULL))  -- scope is both-or-neither
);

-- Mappings are ROLE-ONLY (no inline permissions): a group maps to a named role, never an
-- ad-hoc action set. Same NULL-in-UNIQUE caveat as grants: partial unique indexes, NULL app
-- folded to '*'.
CREATE UNIQUE INDEX idx_group_mappings_uq_scoped
  ON group_role_mappings(provider, group_ref, role_key, scope_type, scope_value, COALESCE(app, '*'))
  WHERE scope_value IS NOT NULL;
CREATE UNIQUE INDEX idx_group_mappings_uq_global
  ON group_role_mappings(provider, group_ref, role_key, COALESCE(app, '*'))
  WHERE scope_value IS NULL;

CREATE INDEX idx_group_mappings_ref ON group_role_mappings(provider, group_ref);
```

Rules:

- Applies to `type='user'` principals only. Service principals have no IdP groups; they use
  explicit grants exclusively.
- `group_ref` format is normalized to `<org>/<team>` lowercase (GitHub team slug, not display
  name). Document the exact normalization in code so admin input and identity data match.
- A user with no matching mapping and no explicit grant simply has zero permissions — that is
  the correct default (lazily created, unprivileged until granted or matched).

### Audit

```sql
-- domain events: what actually changed (produced by apps)
CREATE TABLE audit_events (
  id                  TEXT PRIMARY KEY,           -- UUIDv7 = time-sortable
  request_id          TEXT NOT NULL,              -- correlates with auth log
  principal_id        TEXT REFERENCES principals(id) ON DELETE SET NULL,
  principal_label     TEXT NOT NULL,              -- SNAPSHOT, survives principal deletion
  capability_token_id TEXT,                       -- set when acting under a capability; principal_id is NULL then
  app                 TEXT NOT NULL,              -- self-asserted caller id (audit() carries no token; see hard req 3)
  action              TEXT NOT NULL,              -- 'project.settings.update'
  resource_type       TEXT NOT NULL,              -- 'project'
  resource_id         TEXT,
  diff                TEXT CHECK (diff IS NULL OR json_valid(diff)),       -- {"field":["old","new"]}
  metadata            TEXT CHECK (metadata IS NULL OR json_valid(metadata)),
  created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_audit_resource  ON audit_events(resource_type, resource_id, created_at);
CREATE INDEX idx_audit_principal ON audit_events(principal_id, created_at);
CREATE INDEX idx_audit_request   ON audit_events(request_id);

-- auth log: every authenticate()/redeemCapability() outcome (produced by IAM Worker)
CREATE TABLE auth_log (
  id                  INTEGER PRIMARY KEY,        -- plain rowid: densest table, cheapest insert, never FK'd
  request_id          TEXT NOT NULL,
  app                 TEXT NOT NULL,              -- aud-derived (verified) when a valid token was presented; self-asserted otherwise
  kind                TEXT NOT NULL CHECK (kind IN ('authenticate','redeem')),
  principal_id        TEXT REFERENCES principals(id) ON DELETE SET NULL,
  capability_token_id TEXT,                       -- set for kind='redeem'
  decision            TEXT NOT NULL CHECK (decision IN ('allow','deny')),
  reason              TEXT,                        -- failure reason on deny; 'groups_unavailable' flag noted here too
  created_at          INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX idx_auth_log_principal ON auth_log(principal_id, created_at);
CREATE INDEX idx_auth_log_request   ON auth_log(request_id);
```

Schema rationale the implementer must preserve:

- **`principal_label` is a snapshot** in `audit_events`. Grants and principals get
  revoked/deleted; the audit trail must still show who acted then. FK is `ON DELETE SET NULL`
  so the row survives. Current state mutates; history is immutable. For capability-driven
  events, `principal_id` is NULL, `capability_token_id` is set, and `principal_label` snapshots
  the token's label (fallback `capability:<id>`).
- **`request_id` on both audit tables** gives the auth-outcome ↔ domain-change correlation
  (join on `request_id`). The IAM Worker issues it in the request context.
- **Different ID strategies are intentional:** UUIDv7 for `audit_events`/`principals`/`grants`
  (time-sortable, generated in-Worker), plain `INTEGER PRIMARY KEY` (rowid) for `auth_log`
  (densest table, cheapest insert, never referenced). Note: do **not** use `AUTOINCREMENT` —
  in SQLite it is the _more_ expensive variant and buys nothing here. Use UUIDv7 everywhere we
  generate our own string ids — including `grants.id` and any other entity above.
- **Per-`can()` decision logging is deliberately out of scope for v1.** `can()` is a local pure
  function (hard requirement 4), so the IAM Worker cannot observe individual checks, and a
  report-back channel (batched `recordDecision` RPC from the SDK) is the most complex part of
  the system for the least value at internal scale. The auth log (every authenticate/redeem
  outcome) plus domain audit events cover the trail. If per-check logging is ever needed, it is
  an additive change (new RPC + table); design nothing for it now.
- Grant/revoke of roles is itself a domain event → write it to `audit_events`. So `grants`
  rows can be hard-deleted on revoke without losing history.
- **`diff` may contain sensitive values** (settings can hold secrets). The SDK's `DomainEvent`
  type should document that apps must redact secret material before passing `diff`/`metadata`;
  the IAM Worker stores what it receives verbatim.

Explicitly **out of scope** (do not build, but keep schema additive so these can be added later):
scope/role **hierarchy & containment** (one scope nesting inside another — that would be ReBAC;
apps resolve their own hierarchy and pass the right coordinate), role inheritance, explicit
**Deny** / conditions / ABAC, resource-level ACLs (grant on a single entity), per-`can()`
decision logging. **In scope now** (and implemented): multi-dimension flat scoping, app-declared
vocabulary, admin-composed custom policies, and inline ad-hoc grants.

### Capability tokens (anonymous, scoped, short-lived)

A third credential type alongside user/service principals, for **anonymous, scoped, short-lived
access** — e.g. a shareable link that lets a client view report Q2 _and_ submit feedback on it,
expiring in 30 days. The distinguishing question is: **does the credential carry an identity and
a role (→ principal), or just a set of concrete capabilities and a short lifecycle
(→ capability token)?** A long-lived API key with a role is a service principal, not a
capability. A share link is a capability.

**Storage and assignment are deliberately separate from principals** (different lifecycle, no
roles, no identity), but the **redeem output and `can()` ergonomics are unified** with principals
(see SDK). So the app uses one `can(action, resource)` shape regardless of credential type; only
how the permission list was populated differs (principal: via roles; capability: directly). This
is the answer to "why doesn't it use the same assignment as everything else": assignment differs
on purpose (capabilities have no role indirection — that would be pointless over a one-shot
token), but evaluation/use is unified, which is where uniformity actually helps.

```sql
CREATE TABLE capability_tokens (
  id          TEXT PRIMARY KEY,                 -- UUIDv7
  token_hash  TEXT NOT NULL UNIQUE,             -- SHA-256 of the token; never store plaintext
  label       TEXT,                             -- 'Client ACME — report Q2', human-readable
  issued_by   TEXT REFERENCES principals(id),   -- resolved server-side at issue time, never self-asserted
  expires_at  INTEGER,
  max_uses    INTEGER,                           -- NULL = unlimited (see note)
  used_count  INTEGER NOT NULL DEFAULT 0,        -- incremented on EVERY successful redeem (telemetry)
  revoked_at  INTEGER,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch())
);

-- what the token can do: 1..N (action, resource) pairs
CREATE TABLE capability_grants (
  token_id  TEXT NOT NULL REFERENCES capability_tokens(id) ON DELETE CASCADE,
  action    TEXT NOT NULL,                       -- 'report.read' | 'report.feedback.create'
  resource  TEXT NOT NULL,                       -- 'report:q2-acme'
  PRIMARY KEY (token_id, action, resource)
);
```

Rules the implementer must preserve:

- **Store only the hash.** Plaintext token shown once at issue time (like service-token secrets).
  A DB leak must not yield usable tokens. Tokens are high-entropy (128+ bits) random strings.
- **Exact match, no wildcards.** Unlike roles (which use `*`/`prefix.*` because they are bundles),
  capability grants match the listed `(action, resource)` pairs **exactly**. Wildcards in a
  capability are a way to accidentally grant more than intended.
- **Resource strings must be unambiguous across apps.** Capabilities are not bound to a
  redeeming app — any app can redeem any token (apps are trusted). To prevent a silent
  collision (two apps both using `report:q2` for different things), resource type prefixes
  (`report:`, `invoice:`, …) are a single shared namespace: maintain the list of resource
  types alongside the action naming convention, one owner app per type. No enforcement
  mechanism in v1 — convention only.
- **Delegation rule: you can only delegate what you can do.** Capabilities live _outside_ Access
  on a public path, so issuance is the escalation point. The issuer is resolved server-side from
  forwarded Access credentials (never a self-asserted principal id), and `issueCapability()`
  verifies the issuer holds **every** delegated action via the same matching as `can()` — see
  the RPC section. Without this, any viewer (or app bug) could mint write capabilities.
- **`max_uses` is a coarse whole-token cap, or omit it.** With multiple actions per token, a
  per-redeem counter is confusing (read + feedback + a refresh burns through it unexpectedly).
  v1: rely on `expires_at`; treat `max_uses` as an optional blunt ceiling on total redeems, not
  per-action. Per-action limits are a later refinement, not v1. `used_count` is incremented on
  every successful redeem regardless of `max_uses` — usage telemetry is free.
- **Mutating capabilities need extra care.** A read link leaking means "someone saw the report";
  a write capability (`report.feedback.create`) leaking means "someone wrote under the issuer's
  share". For write-carrying capabilities: shorter expiry, consider per-token rate limiting, and
  audit both the redeem and each resulting domain action.
- **Capability lives outside Access** (the redeeming endpoint is on a Bypass path / a domain not
  behind Access). The capability token _is_ the authorization; the path being public just means
  Access isn't gating it. This is the report-share-link pattern — do not use a bare Bypass prefix
  without a token for anything that isn't meant to be permanently, fully public.
- **Token-in-URL leakage is accepted, with mitigations.** A token in the URL path is what makes
  a share link shareable, but it lands in browser history and server logs. Short expiry (above)
  is the main mitigation; additionally, any page that renders or links tokenized URLs must send
  `Referrer-Policy: no-referrer` so the token never leaks to third parties via the referrer
  header.

## IAM Worker RPC surface

`WorkerEntrypoint` with these methods. Inputs/outputs are plain serializable objects.

```ts
authenticate(input: {
  app: string;                 // self-asserted; superseded by the aud-derived app id on valid tokens (JWT section)
  token: string | null;        // Cf-Access-Jwt-Assertion value
  cookie: string | null;       // CF_Authorization cookie value, for get-identity (users only)
  origin: string | null;       // the app's own origin (for get-identity; see JWT section)
  requestId: string;
}): Promise<
  | { ok: true; principal: {
        id: string; type: 'user'|'service'; label: string;
        permissions: { action: string;
                       scope: { type: string; value: string } | null;   // null = global / all scopes
                       source: 'grant' | 'bootstrap' | `group:${string}` }[];
        requestId: string };
      groupsUnavailable?: true }   // get-identity failed; explicit grants only this request
  | { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' }
>;

audit(event: {
  app: string; requestId: string;
  principalId: string | null;            // NULL for capability-driven events
  principalLabel: string;                // snapshot (token label for capabilities)
  capabilityTokenId?: string;            // set for capability-driven events
  action: string; resourceType: string; resourceId?: string;
  diff?: unknown; metadata?: unknown;
}): Promise<void>;   // fire-and-forget on caller side

// Capability tokens — anonymous, scoped. Separate from authenticate(): no identity.
redeemCapability(input: { app: string; token: string; requestId: string }): Promise<
  | { ok: true; capabilities: { action: string; resource: string }[];
      tokenId: string; label: string | null }
  | { ok: false; reason: 'unknown' | 'expired' | 'revoked' | 'exhausted' }
>;

issueCapability(input: {
  app: string;
  token: string | null;        // ISSUER's Access JWT — issuer is resolved server-side
  cookie: string | null;       // issuer's CF_Authorization cookie (group-derived permissions count too)
  origin: string | null;
  requestId: string;
  grants: { action: string; resource: string;
            scope?: { type: string; value: string } | null }[];  // scope = the delegation-check coordinate ONLY (not stored)
  label?: string; expiresAt?: number; maxUses?: number;
}): Promise<
  | { ok: true; token: string; id: string }      // plaintext token returned ONCE
  | { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal'
                        | 'disabled' | 'not_allowed' }
>;
```

- `authenticate()` validates the JWT, resolves the principal by `(type, external_id)`, and
  computes the `permissions` array as the **union of three sources**:
  1. **Explicit grants** — active non-expired rows in `grants` for this principal
     (`expires_at IS NULL OR expires_at > unixepoch()`), filtered to the calling app
     (`grants.app = <app>` OR `grants.app IS NULL`). A role-based grant expands its `role_key`
     into patterns via the (app-aware) role source; an inline grant adds its `permissions`
     JSON patterns directly. Each entry carries the grant's `(scope_type, scope_value)` as
     `scope` (both NULL → `scope: null`). Source: `'grant'`.
  2. **Group-derived roles** (users only) — fetch IdP group membership via get-identity, match
     each `group_ref` against `group_role_mappings` (also app-filtered), expand the matched
     roles into permissions. Source: `` `group:${group_ref}` ``.
  3. **Bootstrap admins** (users only) — see Admin surface. Source: `'bootstrap'`.
     Dedupe the union. The `source` field exists for debuggability ("why does this user have this
     permission?" in the admin UI) — `can()`/`scopedTo()` ignore it.
- Every `authenticate()` call writes one `auth_log` row (`kind='authenticate'`,
  decision allow/deny, failure reason on deny) via `ctx.waitUntil()`. The `app` column holds
  the aud-derived id when the token validated, the self-asserted id on failure paths.
- **User principals: claim-then-lazy resolution.** For a valid identity-login JWT, resolve the
  principal in three ordered steps:
  1. **By `sub`** — `(type='user', external_id = sub)`. A returning user; refresh `email`/`label`
     if the token's email changed.
  2. **By invited email (claim)** — no `sub` match → look for an _invited_ row
     `(type='user', email = payload.email, external_id IS NULL)`. If found, **claim it**: set
     `external_id = sub` and `label = payload.email` in one statement. The principal — and any
     grants an admin pre-created on it (see Admin surface → invite) — was waiting for this login;
     after the claim the user immediately has those permissions. Match strictly on the
     **IdP-verified `payload.email`** from the validated token, never a self-asserted value.
     (Optionally write an `iam.principal.claim` audit event.)
  3. **Lazy create** — neither matched → insert `(type='user', external_id = sub,
     email = label = payload.email)` with zero grants; unprivileged until granted or matched.

  This is what lets an admin authorize someone **before their first login**: identity stays keyed
  by the stable `sub` (an email change/reassignment after claim only updates `label`), while
  `email` serves purely as a one-shot claim matcher for the pre-login window. Residual risk: if an
  invited email is reassigned to a different person before first login, that person claims the
  grant — narrow window, mitigate with invite expiry later (out of scope v1). Service principals
  are the opposite: always created up-front by provisioning, never lazily and never invited — an
  unknown `common_name` is `unknown_principal`.
- Wildcard matching (`*`, `prefix.*`) happens in TypeScript, not SQL.
- `redeemCapability()` hashes the token and validates + increments in a **single statement**
  to avoid races:
  ```sql
  UPDATE capability_tokens SET used_count = used_count + 1
  WHERE token_hash = ?
    AND revoked_at IS NULL
    AND (expires_at IS NULL OR expires_at > unixepoch())
    AND (max_uses IS NULL OR used_count < max_uses)
  RETURNING id, label;
  ```
  Zero rows affected → one follow-up `SELECT` by `token_hash` to classify the failure
  (`unknown` / `expired` / `revoked` / `exhausted`). On success, return the token's full list
  of `(action, resource)` grants plus its label (the SDK uses it as the audit label snapshot).
  Write an `auth_log` row (`kind='redeem'`, `principal_id = NULL`, `capability_token_id` set).
  No identity is returned — capabilities are anonymous.
- `issueCapability()` resolves the **issuer** from the forwarded credentials exactly like
  `authenticate()` (same failure reasons), then enforces the **delegation rule**: every
  requested grant's `action` must be covered by the issuer's resolved permissions, using the
  same wildcard matching as `can()`, scoped to the grant's `scope` (`{ type, value }`) if
  provided (omitted → the issuer must hold the action globally). Any uncovered action →
  `not_allowed`, nothing created. `scope` is used only for this check; the stored capability
  grant is just `(action, resource)`. On success: generate a 128+ bit random token, store only its SHA-256
  hash plus the grant rows with `issued_by` = the resolved principal id, return the plaintext
  **once**, and write an `iam.capability.create` audit event (recording issuer, label,
  grants — never the plaintext). Revocation sets `revoked_at` and writes
  `iam.capability.revoke`; it takes effect immediately (every redeem re-checks).

## Client SDK (`@firma/iam-client`)

Thin layer over the binding. Bakes the caller `app` id into the constructor so app code can
never forget or mistype it.

```ts
export class IamClient {
	constructor(private binding: Service, private appId: string) {}
	// reads Cf-Access-Jwt-Assertion, CF_Authorization cookie, origin, cf-ray from the request
	async authenticate(req: Request): Promise<AuthContext | AuthFailure> {
		/* ... */
	}
	async redeemCapability(
		req: Request,
		token: string,
	): Promise<Capability | CapabilityFailure> {/* ... */}
	// forwards the requester's credentials as the issuer — see delegation rule
	async issueCapability(
		req: Request,
		input: IssueCapabilityRequest,
	): Promise<IssuedCapability | IssueFailure> {/* ... */}
}

export interface AuthFailure {
	ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled'
	status: 401 | 403 // missing/invalid → 401; unknown_principal/disabled → 403
}

export class AuthContext {
	readonly ok: true
	can(action: string, scope?: { type: string; value: string }): boolean // local, pure: point check; no scope → global perms only
	scopedTo(action: string, dimension: string): string[] | null // local, pure: set of scope values in ONE dimension (REQUIRED)
	audit(event: DomainEvent): Promise<void> // attaches app/principal/requestId
}

// Anonymous capability — no identity, just a set of (action, resource) abilities.
// Same can() ergonomics as AuthContext, but exact-match and resource-keyed (no wildcards).
export class Capability {
	readonly ok: true
	can(action: string, resource: string): boolean // local, pure: exact match
	audit(event: DomainEvent): Promise<void> // attaches capabilityTokenId + label, principalId = null
}

// SDK utility — resolves the three-state scope into a single value the app controls
export function applyScope<T>(scope: string[] | null, branches: {
	all: () => T // scope === null  → unrestricted (admin / global grant)
	some: (values: string[]) => T // scope.length > 0 → filter to these (opaque, app-owned) scope values
	none: () => T // scope === []    → no access; return empty, do NOT query
}): T
```

- `authenticate()` reads `Cf-Access-Jwt-Assertion`, the `CF_Authorization` cookie (parsed from
  the `Cookie` header), the request's own origin (from `req.url`, for get-identity), and
  `cf-ray` (fallback `crypto.randomUUID()`) from the request, calls the binding, and returns
  either an `AuthContext` or a typed `AuthFailure`. All result types share the `ok`
  discriminant — app code branches on `auth.ok`, and `AuthFailure.status` gives the correct
  401/403 mapping so apps don't re-derive it.
- `audit()` auto-injects `app`, `principalId`, `principalLabel`, `requestId` from the context —
  the app supplies only the domain-specific fields. `Capability.audit()` injects
  `capabilityTokenId` and the token label instead, with `principalId = null`.
- **`can(action)` without a scope matches global permissions only.** A permission entry with
  `scope === null` satisfies any check; an entry scoped to a `{ type, value }` coordinate
  satisfies `can(action, { type, value })` for that same pair (and contributes to
  `scopedTo()`), but does **not** satisfy a scope-less `can(action)` — "may do X in some scope"
  must never widen into "may do X here". This mirrors the delegation rule in `issueCapability()`
  (omitted `scope` → the issuer must hold the action globally). Apps pass `{ type, value }`
  whenever the action concerns a scoped resource; scope-less `can()` is for genuinely global
  actions only.
- **`can()` is enforcement (a point check); `scopedTo()` is scoping (the set).** `can()` answers
  "may this principal do X in scope S?" → 403/allow. `scopedTo()` answers "which scope values
  may this principal do X on within dimension D?" → used to filter lists/queries. Both are local
  pure functions over the already-resolved `permissions` array — neither makes a binding call.
  `scopedTo('project.read', 'organization')` filters permissions whose `action` matches
  (wildcards included, `project.*` matches `project.read`) and, among those, collects the
  `scope.value` of entries in the `'organization'` dimension. Entries in a **different** dimension
  are ignored — they neither restrict nor widen the requested one.
- **`scopedTo()` returns `string[] | null` and the `null` is load-bearing.** `null` means
  _unrestricted_ — the principal holds the action globally (a grant or group mapping with
  `scope === null`, e.g. an admin) and may see **all** values in the dimension; a matching global
  entry short-circuits to `null` (it dominates any scoped entries). An empty array `[]` means
  _no access within this dimension_. These are three distinct states; never collapse `null` into
  `[]` or vice versa: `null` → no filter, `[]` → empty result, non-empty → `WHERE col IN (...)`.
- **Use `applyScope()` to consume the result** so the three-state logic (and the empty-`IN ()`
  SQL trap) is handled once in the SDK, not re-implemented per app. The app supplies what `all` /
  `some` / `none` mean for its own query; the SDK guarantees `none` short-circuits without
  emitting `WHERE id IN ()`. Filtering must happen at the data layer (`WHERE id IN (...)`), never
  by loading everything and filtering in memory.
- **Integration contract: apps key their domain rows by their own scope values.** Scope values
  are **app-owned** — Propustka stores and returns them opaquely, so `scopedTo()` hands back
  exactly the strings the app put on grants. `WHERE col IN (...)` works because the app's own
  tables already carry those values (a slug or id the app controls). An app whose data can't be
  keyed by a scope value in some dimension simply doesn't scope grants in that dimension.
- **Scope is generic, flat, multi-dimensional — and `dimension` is REQUIRED.** A grant carries a
  `(scope_type, scope_value)` pair; an app may use several independent dimensions at once
  (e.g. `organization` and `project`). Because more than one dimension can coexist, `scopedTo`'s
  `dimension` argument is **mandatory** — the caller must say which one. (The old single-`project`
  dimension and its YAGNI deferral were intentionally resolved: a second dimension appeared, so
  the generic flat model is now built.) Dimensions are flat and **independent** — there is no
  containment; an app needing hierarchy resolves it itself and passes the right coordinate.
- Ship `FakeIamClient` with identical interface, selected by an env flag for `wrangler dev`:
  fixed identity, `can()` → true, `scopedTo()` → `null`, `redeemCapability()` → a fake
  capability with `can()` → true. Accept an optional `deny: string[]` (action patterns) in its
  constructor so apps can exercise their 403 paths in dev — an unconditional allow-all means
  forbidden branches are never seen until production.
- Export a shared, typed `DomainEvent` so apps converge on one shape: `action` (dotted
  convention), `resourceType`, `resourceId`, `diff`, `metadata` (free JSON for domain specifics).
  Document on the type that `diff`/`metadata` must be redacted by the app before passing —
  audit storage is verbatim and long-lived.

App usage target:

```ts
const iam = new IamClient(env.IAM, 'app-projects') // once
const auth = await iam.authenticate(req)
if (!auth.ok) return new Response(auth.reason, { status: auth.status }) // 401 or 403
if (!auth.can('project.settings.update', { type: 'project', value: id })) {
	return new Response('forbidden', { status: 403 })
}
// ... do the work ...
ctx.waitUntil(
	auth.audit({
		action: 'project.settings.update',
		resourceType: 'project',
		resourceId: id,
		diff,
	}),
)
```

Listing/filtering by scope:

```ts
const scope = auth.scopedTo('project.read', 'project') // dimension is required
const projects = applyScope(scope, {
	all: () => db.listAllProjects(),
	some: (values) => db.listProjects({ ids: values }), // WHERE scope_value IN (...)
	none: () => [], // empty result, no query issued
})
```

Minting a share link in-flow (delegation-checked against the current user):

```ts
const issued = await iam.issueCapability(req, {
	grants: [
		{
			action: 'report.read',
			resource: `report:${id}`,
			scope: { type: 'project', value: projectId },
		},
		{
			action: 'report.feedback.create',
			resource: `report:${id}`,
			scope: { type: 'project', value: projectId },
		},
	],
	label: `Share: report ${id}`,
	expiresAt: in30Days,
})
if (!issued.ok) return new Response('forbidden', { status: 403 }) // e.g. not_allowed
// issued.token — show once, never persisted
```

Public share-link endpoint (capability, no Access, no identity):

```ts
// on a Bypass path e.g. reports.firma.cz/r/<token>
const cap = await iam.redeemCapability(req, token)
if (!cap.ok) return new Response('invalid or expired link', { status: 404 })

if (req.method === 'GET' && cap.can('report.read', `report:${id}`)) {
	return renderReport(id)
}
if (
	req.method === 'POST' && cap.can('report.feedback.create', `report:${id}`)
) {
	await saveFeedback(id, body)
	ctx.waitUntil(
		cap.audit({
			action: 'report.feedback.create',
			resourceType: 'report',
			resourceId: id,
		}),
	) // principalId null, capabilityTokenId attached
	return new Response(null, { status: 201 })
}
return new Response('forbidden', { status: 403 })
```

## Admin surface

A minimal admin API (and optionally a small UI) on the IAM Worker, itself behind Access with
an admin-only policy, to manage principals, grants, **group→role mappings**, **app schemas**,
and **custom policies**. Beyond the Access policy, every `/admin/*` handler **re-checks `can('iam.admin')` in-Worker**
(a pinned sentinel action — only the `admin` role's `*` and bootstrap admins hold it) and
returns `403` otherwise, so a misconfigured Access policy can't expose admin writes.
CRUD on `grants` must write a domain audit event (`iam.grant.create` / `iam.grant.revoke`) —
IAM-entity changes are the most audit-sensitive of all. Keep it boring REST.

**Inviting a user before first login.** Users are otherwise lazily created on first
`authenticate()`, so an admin cannot grant to someone who has never logged in. To pre-authorize a
specific person, `POST /admin/principals` with `{ email }` creates an _invited_ user principal
(`external_id` NULL) that grants can immediately target; the stable Access `sub` is bound on that
user's first login (the claim step — see RPC section). Writes `iam.principal.invite`. The admin
then adds grants to the invited principal exactly like any other. (Team-wide pre-authorization is
expressed instead via group→role mappings; invite is for authorizing one named person ahead of
time.) `DELETE /admin/principals/{id}` of a still-invited (unclaimed) principal just cancels the
invite.

**App schemas (declare-in-code, reconcile-in).** An app's authz vocabulary is not edited in
the admin UI — it's declared in the app's code and pushed:

- `PUT /admin/apps/:app/schema` — idempotent reconcile of an `AppSchema` (scope dimensions,
  action catalog, `origin='app'` roles). Upserts and prunes `origin='app'` rows; **never**
  touches `origin='custom'`. Each role's patterns are validated against the body's own action
  catalog (`isActionAllowed`) — an unknown action is a 400. Writes `iam.app.schema.reconcile`.
  The `:app` segment must be a configured `ACCESS_APPS` value.
- `GET /admin/apps/:app/schema` — the reconciled vocabulary (scopes, actions, `origin='app'`
  roles). `GET /admin/apps` lists the configured app ids.
- `GET /admin/roles?app=<app>` — the grantable role list for an app: the built-in `admin`
  plus the app's DB roles (`origin='app'` + `'custom'`), so the UI can populate pickers and
  flag dangling `role_key`s. Built-ins win on a key collision.

**Custom policies (admin-composed bundles).** On top of the app's reconciled roles, an admin
can compose `origin='custom'` policies (named action-pattern bundles) without touching app code:

- `GET|POST /admin/apps/:app/policies`, `PUT|DELETE /admin/apps/:app/policies/:key`
  (`iam.policy.create` / `iam.policy.update` / `iam.policy.delete`). Patterns are validated
  against the app's action catalog; a key may not collide with a built-in; update/delete refuse
  `origin='app'` rows (reconcile owns those).

**Grants are role-or-inline.** `POST /admin/grants` (and the api-key flow) take EITHER a
`roleKey` (validated as a known role for the app) OR an inline `permissions` array (each
pattern validated against the app's catalog) — exactly one. `scopeType`/`scopeValue` are
both-or-neither; an `app` of null or a configured `ACCESS_APPS` value. Writes
`iam.grant.create` / `iam.grant.revoke`.

CRUD on `group_role_mappings` works the same way as grants: `POST/DELETE /admin/group-mappings`
writes `iam.groupmapping.create` / `iam.groupmapping.delete` audit events. A mapping is
**role-only** (no inline permissions). This is where "team `my-org/core-devs` → editor in
scope X" is configured as data, not code.

Capability tokens are issued/revoked here too: `POST /admin/capabilities` (body: grants list,
label, expiry, optional max_uses) calls `issueCapability()` with the **admin's own forwarded
credentials** — the delegation rule applies to admins like everyone else (admins typically hold
`*`, so it passes) — and returns the plaintext token once; `DELETE /admin/capabilities/{id}`
revokes it. Both write the corresponding `iam.capability.create` / `iam.capability.revoke`
audit events. Issuing is also exposed as an RPC so apps can mint share links in-flow (e.g. a
"share this report" button) without going through the admin UI.

### Bootstrap: the first admin

The admin API requires admin permissions, but users are created lazily with zero grants —
without a bootstrap, nobody can ever create the first grant. Solve it statelessly:

- Env var `IAM_BOOTSTRAP_ADMINS` (JSON array of emails, normally empty).
- During permission resolution, if the principal is `type='user'` and their email is in the
  list, union a **global `admin` role** into their permissions (source `'bootstrap'`). Nothing
  is written to D1.
- The bootstrap admin then creates real grants via the admin API and the var is emptied.
  Because it is resolution-time only, removing the email removes the power on next
  `authenticate()` — no cleanup migration.

### API key (service token) provisioning

The admin must be able to issue API keys for machine callers. An API key here **is** an Access
service token — we do not invent our own key format. Provisioning is a single admin action that
orchestrates two systems: it mints the credential in Cloudflare Access and records the principal

- grants in IAM, in one flow.

Endpoint: `POST /admin/api-keys` with body
`{ label, type: 'service', app?, scopeType?, scopeValue?, roleKey | permissions, expiresAt? }`.
(The role-or-inline choice is validated against the app's vocabulary — `roleKey` a known role,
inline `permissions` patterns against the action catalog — before anything is minted;
`scopeType`/`scopeValue` are both-or-neither.)

Flow (server-side, in the IAM Worker):

1. **Mint the service token in Access** via the Cloudflare API:
   `POST /accounts/{account_id}/access/service_tokens` with the chosen `name` (use the IAM
   principal label) and optional `duration`. The call needs a Cloudflare API token with the
   _Access: Service Tokens Edit_ permission, stored as a Worker secret (`CF_API_TOKEN`,
   `CF_ACCOUNT_ID`).
2. The response returns `client_id`, `client_secret`, and the token id. **`client_secret` is
   shown by Cloudflare exactly once** — surface it in the API response and the UI immediately,
   with a clear "copy now, not retrievable later" warning. Never persist the secret.
3. **Create the IAM principal**: insert into `principals` with `type='service'`,
   `external_id = client_id` (this is what the service-token JWT carries as `common_name`),
   `label`, fresh UUIDv7 id.
4. **Create the grant(s)**: insert into `grants` linking the new principal to the chosen role
   (or inline permissions) scoped to `(scopeType, scopeValue)` (or NULL/NULL for global) and
   `app`, with `expires_at` mirroring the token duration if set.
5. **Write audit events**: `iam.apikey.create` (with token id + label, never the secret) and
   `iam.grant.create`.
6. **Add the token to the app's Access policy** so it can actually reach the target app:
   the relevant Access application needs a **Service Auth** policy that includes this service
   token. Either (a) the admin maintains one shared Service Auth policy per app and the new
   token is added to it via the Access API (`PUT` the application's policy / include the token
   id), or (b) document that this step is manual in the dashboard for v1. Pick (a) if the Access
   policy API for service-token inclusion is available to us; otherwise (b) with a clear TODO.
   This step is what links "IAM knows the permissions" to "Access lets the call through".

Failure handling (no distributed transaction available):

- If step 1 fails → return error, nothing created. Clean.
- If a later step fails after the token was minted → the orphaned Access token must be cleaned
  up (`DELETE` the service token) or surfaced as a reconciliation item. Implement a best-effort
  rollback: on failure after mint, attempt to delete the token; if that also fails, write an
  `iam.apikey.orphaned` audit event with the token id for manual cleanup. Do **not** leave a
  minted token with no IAM record silently.

Revocation: `DELETE /admin/api-keys/{principalId}` must (1) delete the Access service token via
API, (2) remove the token from the app's Service Auth policy, (3) hard-delete the `grants` rows,
(4) soft-disable or delete the principal, (5) write `iam.apikey.revoke`. Revocation takes effect
immediately because service auth has no session — each request is re-evaluated.

Rotation: provide `POST /admin/api-keys/{principalId}/rotate` that generates a new
`client_secret` for the existing token via the Access API (token id and IAM principal unchanged),
returns the new secret once, and writes `iam.apikey.rotate`. Plan for rotation from day one so a
year-out mass expiry doesn't surprise us.

Human (user) principals are created lazily on first successful `authenticate()` instead — see
the RPC section — so this provisioning flow is specifically for `type='service'` keys.

## Operational notes

- Per-isolate cache of group membership (from get-identity) with short TTL (tens of seconds)
  is fine — it matches Access session revocation latency anyway. Cache must be safe to be empty
  (fail to get-identity). There is no resolved-principal cache: grants are always read from D1
  at `authenticate()`, so grant/revoke takes effect immediately.
- Retention differs: prune `auth_log` after a few weeks; keep `audit_events` long.
  A scheduled handler (cron trigger) deletes old `auth_log` rows — the rowid is
  time-correlated, so pruning by `created_at` (or by max rowid snapshot) needs no extra index.
  Optionally spool pruned rows to R2 if `audit_events` ever grows large (probably never for
  internal scale — don't pre-build).
- The IAM Worker is the single audit choke point; this is how we also solve the Access free-tier
  24h log retention limit (we keep our own complete auth trail).

## Acceptance criteria

1. An app behind Access can authorize a request with one binding call + local `can()` checks.
2. Missing/invalid token → 401; valid credential mapping to an unknown or disabled principal →
   403; valid principal without permission → `can()` false → 403. The SDK failure object carries
   the status; the three cases are clearly distinct.
3. Every authorized mutation can emit a domain audit event with auto-attached
   caller/principal/request context, written via `waitUntil`, non-blocking.
4. Every `authenticate()`/`redeemCapability()` outcome lands in `auth_log`, and domain events
   for the same request share `request_id` and are joinable. Per-`can()` decision logging is
   explicitly out of scope for v1 and requires no pre-built schema.
5. Deleting a principal/grant preserves historical audit rows with the original
   `principal_label`.
6. Apps run in `wrangler dev` with the fake client, no Access and no IAM Worker required; the
   fake supports a deny-list so 403 paths are testable in dev.
7. Role→permission bundles live in D1 per app (the `roles` table, `origin='app'`/`'custom'`)
   behind the `RoleSource` interface, with a single built-in cross-app `admin = ['*']` in code.
   Resolution is unchanged by the source. Unknown `role_key`s are rejected at grant/mapping
   creation time and resolve to zero permissions if they appear anyway.
8. No per-app secret auth, no scope/role hierarchy or containment, no explicit Deny /
   conditions / ABAC, no resource-level ACLs; schema remains additive for them. Duplicate
   ROLE-based grants/mappings are impossible including the global (`scope_value IS NULL`) case;
   inline grants are intentionally unconstrained (each is its own attachment).
   8a. Each app declares its `AppSchema` (scope dimensions + action catalog + roles) in code and
   reconciles it via `PUT /admin/apps/:app/schema`: the reconcile upserts and prunes
   `origin='app'` rows and never touches `origin='custom'`. Every action pattern (on a role, a
   custom policy, or an inline grant) is validated against the app's action catalog
   (`isActionAllowed` — `*`, exact, or `prefix.*` over a non-empty namespace); unknown actions
   are rejected at write time. A grant carries EITHER a `role_key` OR inline `permissions` —
   exactly one (DB CHECK). Permissions are additive-allow only.
9. Admin can provision an API key: it mints an Access service token, creates the IAM principal +
   grants, returns the secret exactly once, and (manually or automatically) the token is added to
   the target app's Service Auth policy. Revocation deletes the Access token and removes IAM
   grants; a failed mid-flow provisioning never leaves a minted token without an IAM record.
10. All self-generated string ids are UUIDv7.
11. A user in a GitHub team that has a `group_role_mappings` row receives that role's permissions
    automatically (no explicit grant), resolved via get-identity at `authenticate()`; the
    resulting permission entries carry `source: 'group:<org/team>'`. Removing the **mapping**
    removes the permission on the next `authenticate()` (mappings are read from D1). Removing the user's
    **team membership** takes effect once their Access session refreshes against the IdP —
    group data is login-time, not live; immediate revocation requires explicit grants or Access
    session revocation. Group resolution applies to users only, never service principals. A
    get-identity outage degrades to explicit grants with a visible `groupsUnavailable` flag
    (and auth-log note), never a silent denial.
12. `scopedTo(action, dimension)` returns the set of (opaque, app-owned) scope values the
    principal may perform `action` on within `dimension`, or `null` for unrestricted (global)
    access — three distinct states (`null` / `[]` / non-empty) that `applyScope()` consumes
    without ever emitting `WHERE col IN ()`. Resolution is local (no binding call) and filtering
    happens at the data layer. Scope dimensions are generic, flat, and independent (no
    containment); `dimension` is REQUIRED, and entries in another dimension are ignored.
    `can(action)` without a scope is satisfied by global permissions only — a scoped grant never
    satisfies a scope-less check; `can(action, { type, value })` is satisfied by a global entry
    OR an entry scoped to that exact pair.
13. A capability token can carry multiple `(action, resource)` grants (e.g. read a report +
    submit feedback on it); `redeemCapability()` returns the full set with no identity, exposes
    `can(action, resource)` with exact matching (no wildcards), enforces
    expiry/revocation/`max_uses` atomically in one statement, stores only the token hash, and
    returns plaintext once at issue. Redeems and resulting domain actions are logged with
    `principal_id = NULL` + `capability_token_id` for traceability. Capabilities live outside
    Access on a Bypass path; the token, not the path, carries authorization.
14. Issuance enforces the delegation rule: the issuer is resolved server-side from forwarded
    Access credentials (never self-asserted), and every delegated action must be covered by the
    issuer's own permissions (scoped via the optional per-grant `scope` `{ type, value }`
    coordinate), else `not_allowed` and nothing is created.
15. JWT `aud` is validated against the keys of the configured `ACCESS_APPS` map — tokens
    from every onboarded Access application validate; unknown AUDs are rejected. On a valid
    token, the app identity recorded in `auth_log` and the request context is derived from the
    verified `aud`, not from the SDK-passed app id; a mismatch between the two is logged but
    does not fail the request.
16. With an empty database and `IAM_BOOTSTRAP_ADMINS` set, the listed user authenticates with
    global admin permissions (source `'bootstrap'`), can create the first real grants, and loses
    bootstrap power on next `authenticate()` once removed from the env var.
17. An admin can invite a user by email **before they ever log in**: a grant created on the
    invited principal (`external_id` NULL) takes effect on that user's first `authenticate()`,
    which binds their Access `sub` to the pre-created principal (claim). Matching uses the
    IdP-verified token email only; identity remains keyed by `sub` after claim, so a later email
    change does not detach grants or audit history. Resolution order is `sub` → invited-email →
    lazy-create; service principals are never invited.
