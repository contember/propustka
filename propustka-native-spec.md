# Propustka-native auth — spec

How propustka stops _riding on_ Cloudflare Access and becomes the auth layer itself: its own SSO
(any OIDC provider), its own credentials, its own per-app tokens — so apps no longer depend on CF
Access and we no longer pay for / sync with CF Access Teams.

This document is the design of record for the `feat/propustka-native-auth` work. It complements
`iam-service-spec.md` (authz) and `admin-ui-spec.md` (admin).

## Why

Today propustka rides on Cloudflare Access: Access does authn (SSO, the login session, the JWT) +
edge gating + service tokens, and propustka layers authz (principals, grants, roles, scopes) on top
by **resolving the Access JWT over RPC on every request**. That couples us to CF Access (its feature
set, its quirks, its per-seat Teams pricing) and forces a per-request round-trip because the Access
JWT carries only identity.

Pulling authn into propustka removes that coupling — and, because we now issue the token, lets us
**embed the resolved permissions in it** so the SDK authorizes locally with no per-request RPC.

## The real axis (what this design unifies)

The earlier model had three concepts — _session_, _service token / API key_, _capability (share
link)_ — and a user could not tell which to issue. That split was a **false axis**. There are only
two things that actually differ, and one of them turned out not to matter:

1. **Stateful opaque credential vs stateless signed JWT.** This is the ONE axis that matters:

   |                         | **key** (opaque, stored)                       | **jwt** (passthrough)                  |
   | ----------------------- | ---------------------------------------------- | -------------------------------------- |
   | revocation              | yes, instant (delete the row)                  | no — TTL only                          |
   | propustka in the path   | resolve + cache                                | **never**                              |
   | permissions             | may be **live** (via a principal) or inline    | inline, **frozen at issue**            |
   | state stored            | a row (+ audit)                                | **audit only**                         |
   | when to choose          | long-lived / revocable: CI key, personal token, a share link you may want to kill | fire-and-forget, high-volume passthrough, zero per-request dependency on propustka |

   This mirrors AWS exactly: an opaque key ≈ an IAM access key (stored, revocable); a passthrough JWT
   ≈ an STS token (stateless, TTL-bounded, frozen).

2. **Is a principal attached?** This is now just an **optional** property of a credential, not a
   separate concept. A credential with a principal carries that principal's _live_ resolved
   permissions (and is revoked by disabling the principal); a credential without one carries a
   _frozen_ inline grant. A share link is simply "a credential with no principal whose token rides in
   a URL path."

What we deliberately dropped:

- **`max_uses` / `used_count`.** A whole-token use cap conflates _validating_ a token with
  _consuming_ an operation. The real need (e.g. a password-reset link: validate the token any number
  of times, apply the reset exactly once) is **operation-scoped, not token-scoped** — it belongs to
  the app's own state (the reset row is consumed), never to the token. So the token model has no use
  counter. If a true single-use ever returns, it is an explicit `consume` step, not a global counter.

## Decisions (settled with the maintainer)

- **One credential primitive**, not api-key-vs-capability. Optional principal, optional inline
  grants, optional expiry. Transport (URL path for a share link / `Authorization: Bearer` for a
  machine) is an _implementation detail of the consuming rule_, never a separate type.
- **One access-token shape on the wire.** Drop the `kind` discriminator and the exact-match
  capability claim. Every token carries `perms: PermissionEntry[]` and an OPTIONAL `sub`/`ptype`
  (principal) + `label`. `can(action, scope?)` is **always** `permits()` (scopes + wildcards). A
  share link is just narrow scoped entries with no `sub` (and is simply never issued a wildcard).
- **Principal is optional, with intersection semantics** (the 2×2 below).
- **Middleware, not a proxy.** Protected apps are CF Workers we own; each runs a thin SDK middleware
  that verifies a token locally. propustka stays OUT of the data path.
- **Any OIDC provider, configured by env** (discovery-based). `OIDC_ISSUER` + client id/secret;
  endpoints come from `/.well-known/openid-configuration`.
- **TTL-bounded revocation is acceptable.** The hot path is a local verify. TTL is the one
  security knob (see below); `PROPUSTKA_MAX_TOKEN_TTL` caps it, per credential kind.
- **Incremental migration.** The new path runs ALONGSIDE the existing Access path; apps flip one at a
  time; the CF Access machinery is deleted last.

## The unified pipeline

```
HANDLE ──→ resolve ──→ cache ──→ ACCESS TOKEN (JWT) ──→ SDK verifies locally
  session cookie  ─┐                         ┌ cache: cookie       (human)
  api key (bearer) ┼─ propustka resolves ────┼ cache: KV           (machine)     TTL configurable,
  share-link path ─┘  (principal? ∩ inline)  └ cache: isolate mem  (fallback)    capped by env

BYPASS:  passthrough JWT ──→ SDK verifies locally   (no resolve, no cache; audit-at-issue only)
```

Session, API key, and share link are the SAME primitive — an opaque handle that propustka resolves
into a short signed **access token**, which is then verified locally by the app's SDK on every
request (no per-request RPC). They differ only in **where the handle rides** (cookie / header / path)
and **where the minted token is cached** (cookie / KV / isolate memory). The passthrough JWT skips
the whole pipeline: it already _is_ an access token.

> **Honest caveat — TTL is a security knob, not a free lunch.** A longer TTL means fewer mints but
> worse revocation: an already-minted token (cached, or a passthrough JWT) keeps working until it
> expires — exactly like AWS STS, which you cannot revoke mid-life. The _opaque credential_ stays
> instantly revocable (delete the row → it mints nothing further); the already-minted access token is
> TTL-bounded. So: humans get a short TTL (~5 min), machines may opt into a longer one (up to
> `PROPUSTKA_MAX_TOKEN_TTL`, e.g. 24 h). A passthrough JWT is TTL-only by construction.

## The access token (one wire shape)

A signed ES256 JWT (EC P-256, `PROPUSTKA_SIGNING_KEYS`, public set via `getJwks` and
`/.well-known/jwks.json`). One shape, no `kind`:

```
{
  iss,                       // propustka origin
  aud,                       // the app id; the SDK REJECTS a token whose aud is not its app
  iat, exp,
  perms: PermissionEntry[],  // resolved/effective permissions; can() = permits(perms, action, scope?)
  sub?:   principalId,       // present  ⇔ principal-bound
  ptype?: 'user' | 'service',// present  ⇔ principal-bound
  label:  string | null      // principal label, or the credential/jwt label; the audit actor
}
```

- `sub` present → an identified principal; `audit` attributes to it.
- `sub` absent → anonymous (a share link / standalone JWT); `audit` attributes to `label`.
- `can(action, scope?)` is `permits()` everywhere — the exact-match `can(action, resource)` of the
  old capability is gone; a share-link grant is a `PermissionEntry { action, scope: {type, value} }`.

## The credential (one stored primitive)

One table replacing `capability_tokens`, the planned `api_keys`, and the service principal's CF
service token. The opaque secret (`generateToken` 160-bit, `hashToken` SHA-256, prefix `px_`,
plaintext shown once) is the existing capability primitive, reused as-is.

```
credentials
  id           TEXT PK (uuidv7)
  token_hash   TEXT UNIQUE          -- SHA-256; plaintext never stored
  label        TEXT
  principal_id TEXT NULL  → principals(id)   -- present ⇔ principal-bound
  issued_by    TEXT       → principals(id)   -- resolved server-side at issue (delegation audit)
  expires_at   INTEGER NULL
  revoked_at   INTEGER NULL
  created_at   INTEGER

credential_grants                    -- inline perms: a frozen grant and/or a downscope restriction
  credential_id TEXT → credentials(id) ON DELETE CASCADE
  action        TEXT
  scope_type    TEXT NULL
  scope_value   TEXT NULL
```

**Resolution → effective perms** (the 2×2 the maintainer settled):

| `principal_id` | inline grants | effective permissions                              |
| -------------- | ------------- | -------------------------------------------------- |
| set            | set           | `resolve(principal, app) ∩ grants` — personal token / downscope |
| set            | —             | `resolve(principal, app)` — service / personal token (live perms) |
| —              | set           | `grants` — share link / standalone (frozen)        |
| —              | —             | reject (grants nothing)                            |

Then sign an access token with `sub = principal_id ?? absent`, `perms = effective`,
`exp = min(now + ttl, credential.expires_at)`. No use counter.

## The two issue APIs

```
issueKey({ app, <issuer creds>, principalId?, permissions?, label?, expiresAt? })
   → { ok, token: "px_…", id }          // opaque, stored, revocable

issueJwt({ app, <issuer creds>, permissions, label?, expiresAt? })
   → { ok, token: "eyJ…", expiresAt }   // signed, stateless, audit-only
```

- Both are **delegation-checked**: the issuer is resolved server-side from the forwarded credentials
  and may only grant what it itself holds (`findUncoveredGrant`, already implemented). This protects
  share links and passthrough JWTs alike — neither can exceed its issuer.
- `issueKey` writes a `credentials` row (+ `credential_grants`); the transport is the caller's choice.
- `issueJwt` signs an anonymous access token directly (no `sub`), capped by `PROPUSTKA_MAX_TOKEN_TTL`,
  and writes one audit row. There is nothing to revoke — it is TTL-only by design.
- `issueServiceToken` becomes `issueKey({ principalId: <new service principal> })`; `issueCapability`
  becomes `issueKey({ permissions, expiresAt })` with a URL-path transport. (See Migration.)

## Runtime auth — three sources, two mechanisms

The app's SDK middleware (`PropustkaAuth`) handles, per request:

1. **human, via cookie** — `px_session` (opaque) → propustka resolves the principal → mints + caches
   an access token in the host-only `px_token` cookie.
2. **opaque key, via bearer/path** — `Authorization: Bearer px_…` (or a share-link path token) →
   propustka resolves the credential → mints + caches the access token (KV / isolate memory).
3. **passthrough JWT** — `Authorization: Bearer eyJ…` → the SDK verifies it locally; propustka is not
   called at all.

Sources 1–2 share the **resolve-then-cache** mechanism (cache substrate differs; TTL configurable,
env-capped). Source 3 is the **passthrough** bypass. The SDK discriminates a bearer by shape: an
opaque `px_…` is exchanged once and the result cached; an `eyJ…` JWT is verified locally.

The JWKS is fetched once per isolate over the **service binding** (`getJwks`, which never traverses
the Access edge — so it works while propustka's own host is still Access-gated) and cached per
binding; a key rotation (unknown `kid`) forces one refetch. `/.well-known/jwks.json` is also served.

## Rule definitions (per-path credential declaration)

An app declares, per path, **who** may access and — for the key/jwt case — **where** the credential
rides and its **kind**, so the SDK middleware knows how to handle it:

```
{ match: <path glob>,
  credential: { in: 'cookie' | 'header' | 'query' | 'path', name?, kind: 'session' | 'key' | 'jwt' }
             | 'public' }
```

- `kind: 'session' | 'key'` → resolve-then-cache.
- `kind: 'jwt'` → passthrough (middleware does nothing; the app verifies locally and sees a resolved
  request transparently).
- `'public'` → no credential required.

This is the propustka-native successor to today's `AccessRule` (`service-auth | human | public`),
which gated WHO at the CF edge. WHO-is-a-valid-human is decided centrally at login (OIDC +
`HUMAN_EMAIL_DOMAINS` / `HUMAN_EMAILS`); per-path authorization is the app's `can()` check.

## Login flow (OIDC — any provider via discovery)

```
GET /auth/login?redirect=… → PKCE + state in an httpOnly /auth cookie → 302 to the IdP
GET /auth/callback          → exchange code → verify id_token (iss/aud/verified-email)
                            → resolve/lazy-create the principal (by IdP sub + email)
                            → create the SSO session, Set-Cookie px_session, 302 back
GET|POST /auth/logout       → revoke the session, clear the cookie
```

Endpoints + the canonical issuer come from the provider's discovery document
(`${OIDC_ISSUER}/.well-known/openid-configuration`), fetched once per isolate and cached. An
open-redirect guard restricts the return target to the issuer host / configured cookie domain /
localhost.

## Env

`ISSUER`, `PROPUSTKA_SIGNING_KEYS` (secret), `PROPUSTKA_MAX_TOKEN_TTL` (cap on a requested TTL,
per kind defaulting), `SESSION_COOKIE_DOMAIN`, `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`
(secret), `OIDC_SCOPES`, `OIDC_REQUIRE_VERIFIED_EMAIL` — threaded through `oblaka.ts` (vars) /
`.dev.vars` (secrets).

## Migration (from the split model)

- **Wire token**: `PrincipalTokenClaims` + `CapabilityTokenClaims` → one `AccessTokenClaims` (drop
  `kind`, optional principal). The SDK's `RealCapability` collapses into the anonymous variant of
  `RealAuthContext`; `can(action, resource)` consumers move to `can(action, { type, value })`.
- **Tables**: `capability_tokens` (+ `capability_grants`) → `credentials` (+ `credential_grants`).
  `sessions` stays its own table (different birth: OIDC `idp_sub`/`email`) but is the human instance
  of the same primitive and shares the resolve→sign pipeline.
- **RPC**: `mintToken` generalizes to accept a session OR a key source and an optional (capped) TTL.
  `issueServiceToken`/`issueCapability` reduce to `issueKey`; `redeemCapability` becomes the key
  resolution path. `issueJwt` is new. The CF service-token half of `issueServiceToken` is kept
  **add-only** during migration (existing service-token clients keep working behind Access) and
  removed when the last machine app has flipped.
- **CF Access removal (last)**: delete `cfaccess.ts`, `scripts/provision-access*.ts`,
  `reconcile-access`, `ACCESS_APPS`/`TEAM`; rebirth `propustka.access.ts` as the per-path credential
  declaration above. Until then `/auth/*` + `/.well-known/jwks.json` need a `public` carve-out.

## Affected downstream apps (known)

- **poplach** — ingest (`/api/*/envelope`) is already a **public** carve-out + its own `sentry_key`
  KV lookup, independent of propustka; the Sentry-compat path is unaffected. Only the operator UI
  (human) migrates to the OIDC session path.
- **opice** — ingest (`/api/v1/<slug>/…`) authenticates with **CF Access service tokens**
  (`cf-access-client-id` / `cf-access-client-secret`, DSN-packaged). This is the machine path with no
  native equivalent until `issueKey`/api-keys land; opice stays on the Access path until its DSNs are
  reissued as `px_` keys (carried in a header) or as passthrough JWTs. The operator UI migrates
  independently.

## Build order

1. **Core** — unify the access token (`AccessTokenClaims`, build/parse, resolved mapping).
2. **Worker** — `credentials` table + Db, `resolveCredential` (2×2), generalize `mintToken`
   (session|key, capped TTL), `issueKey` + `issueJwt`, repoint capability + service-token onto the
   primitive (CF half add-only).
3. **SDK** — `PropustkaAuth` accepts cookie / `px_` bearer / passthrough JWT; collapse `Capability`
   into the anonymous `AuthContext`.
4. **Rule schema + CF Access removal** — the per-path credential declaration; delete CF Access
   machinery (later slice).

## Follow-ups (not in the foundation slices)

- Propustka-side **KV cache** for minted access tokens (the SDK-side cache lands first; KV is a
  shared optimization for cold isolates).
- **Downscope at mint** (`assume` with a restricting policy beyond what the credential already
  encodes) — a v2 parameter once `issueKey`/`issueJwt` are in.
- **Per-app session cookie via redirect ticket** — for apps not under one registrable domain.
- **Durable signing-key provisioning + rotation runbook.**
