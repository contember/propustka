# Propustka-native auth — spec

How propustka stops _riding on_ Cloudflare Access and becomes the auth layer itself: its own SSO
(Google OIDC), its own API keys, its own per-app tokens — so apps no longer depend on CF Access and
we no longer pay for / sync with CF Access Teams.

This document specifies the model. It complements `iam-service-spec.md` (authz) and
`admin-ui-spec.md` (admin), and is the design of record for the `feat/propustka-native-auth` work.

## Why

Today propustka rides on Cloudflare Access: Access does authn (SSO, the login session, the JWT) +
edge gating + service tokens, and propustka layers authz (principals, grants, roles, scopes,
capabilities) on top by **resolving the Access JWT over RPC on every request**. That couples us to
CF Access (its feature set, its quirks, its per-seat Teams pricing) and forces a per-request
round-trip because the Access JWT carries only identity.

Pulling authn into propustka removes that coupling — and, because we now issue the token, lets us
**embed the resolved permissions in it** so the SDK authorizes locally with no per-request RPC.

## Decisions (settled with the maintainer)

- **Middleware, not a proxy.** Protected apps are CF Workers we own, so each runs a thin SDK
  middleware (`PropustkaAuth`) that verifies a token locally. propustka stays OUT of the data path
  (no reverse proxy, no availability/latency hit on app traffic).
- **Google only** (for now) as the IdP. One OIDC connector; no GitHub-teams / get-identity group
  resolution in v1 (group→role mapping is a later add via the Google Admin SDK if ever needed).
- **Incremental migration.** The new path runs ALONGSIDE the existing Access path; apps flip one at
  a time. The CF Access machinery is deleted last (a follow-up), not in the foundation.
- **TTL-bounded revocation is acceptable** (~5 min). That makes the hot path purely stateless: local
  verify, no denylist, no per-request shared-state check.

## The three-layer token model

| Layer                        | What                                                                  | Lifetime      | Revocation           | Carried in                          |
| ---------------------------- | --------------------------------------------------------------------- | ------------- | -------------------- | ----------------------------------- |
| **SSO session**              | opaque random token → principal (the source of truth for "logged in") | long (30 d)   | instant (delete row) | `px_session` cookie (parent-domain) |
| **Per-app permission token** | signed JWT carrying the resolved `PermissionEntry[]` for ONE app      | short (5 min) | TTL-bounded          | `px_token` cookie (host-only)       |
| **Refresh**                  | mint a fresh permission token from the session                        | —             | —                    | `mintToken` RPC over the binding    |

We did **not** become a JWT issuer for the _session_ — it's opaque (only its SHA-256 hash is stored,
like capability tokens). We DID become an issuer for the _permission token_, because embedding the
permissions is the whole point. Key custody: ES256 (EC P-256), `PROPUSTKA_SIGNING_KEYS` (index 0 =
active signer, all published for rotation), public set served via `getJwks` (and
`/.well-known/jwks.json`).

### Request flow (the SDK middleware, `PropustkaAuth`)

```
1. valid, not-near-expiry px_token  → verify LOCALLY against JWKS → authorize.   (≈99% of requests, no RPC)
2. else → mintToken({ session }) over the binding → set a fresh px_token → authorize.   (≈once per TTL)
3. no/invalid session → 302 the browser to propustka /auth/login?redirect=<here>.
```

The JWKS is fetched once per isolate over the **service binding** (which never traverses the Access
edge — so it works even while propustka's own host is still Access-gated), cached per binding, and
refetched once on a key-rotation (unknown `kid`).

> **Honest caveat:** "no round-trip" means ≈99% of requests, plus one server-side `mintToken` per
> TTL per app — NOT literally never. The win over today (RPC every request) is large, and an
> unexpired token keeps working even if propustka is briefly down (tolerance window = the TTL).

### Login flow (Google OIDC)

```
GET /auth/login?redirect=… → PKCE + state in an httpOnly /auth cookie → 302 to Google
GET /auth/callback          → exchange code → verify id_token (iss/aud/verified-email)
                            → resolve/lazy-create the principal (by Google sub + email)
                            → create the SSO session, Set-Cookie px_session, 302 back
GET|POST /auth/logout       → revoke the session, clear the cookie
```

Open-redirect guard on the return target: only the issuer host, the configured session-cookie
domain, or localhost (dev) are accepted; anything else falls back to the issuer origin.

## The unified credential pipeline (design; partially built)

Three credential SOURCES, one flow — `source → propustka validates → signed token → SDK verifies
locally`. The token's `kind` claim discriminates what it carries; the SEMANTICS stay distinct:

| Source      | Location                                  | Validated by                     | Token `kind` |
| ----------- | ----------------------------------------- | -------------------------------- | ------------ |
| SSO session | `px_session` cookie                       | session lookup (D1)              | `principal`  |
| API key     | `Authorization: Bearer px_…`              | hash lookup (planned `api_keys`) | `principal`  |
| share link  | path pattern `/p/share/:token` (declared) | capability redeem (atomic)       | `capability` |

- **API keys** simplify from the CF service-token pair to a single bearer `px_<random>` (hash-stored)
  — same `generateToken`/`hashToken` primitive capabilities already use. **Built:** the token
  contract carries both kinds; **not yet built:** the `api_keys` table + the bearer validation +
  retiring CF service tokens.
- **Share links** keep their distinct semantics (anonymous, exact-match `(action, resource)`,
  expiry/uses) but flow through the same mint→verify pipeline; minting a short capability token on
  redeem means a single-use link survives an SPA's many sub-requests (one redeem, then local verify).
  `maxUses` then counts MINTS (≈ viewers), not HTTP requests. **Not yet built.**

## What this slice (the foundation PR) builds

- `@propustka/core`: the token contract (`token.ts`) — `principal` + `capability` claim shapes,
  build/parse helpers, the public-JWKS types; `mintToken`/`getJwks` added to `IamRpc`.
- `@propustka/worker`: ES256 signing (`signing.ts`), `sessions` table + Db access, Google OIDC
  client (`oidc.ts`), `mintToken`/`getJwks` RPC, and the public `/auth/*` + `/.well-known/jwks.json`
  HTTP surface.
- `@propustka/client`: `PropustkaAuth` — local verify + session middleware (jose).
- `examples/app`: wired onto `PropustkaAuth`.

New env: `ISSUER`, `PROPUSTKA_SIGNING_KEYS` (secret), `SESSION_COOKIE_DOMAIN`, `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET` (secret) — threaded through `oblaka.ts` (vars) / `.dev.vars` (secrets).

## Follow-ups (NOT in this slice)

1. **Own API keys** — `api_keys` table + bearer validation; repoint `issue/revoke/rotateServiceToken`
   off the CF Access API onto it; drop `cfaccess.ts`'s service-token half.
2. **Unified share-link pipeline** — path-pattern credential declaration + capability tokens.
3. **Access bypass during migration** — `/auth/*` and `/.well-known/jwks.json` need a CF Access
   `public` carve-out (a `public` rule in `propustka.access.ts`) while the propustka host is still
   gated, so the browser and the app-side SDK reach them.
4. **Delete CF Access machinery** — `cfaccess.ts` (reusable policies/apps reconcile),
   `scripts/provision-access*.ts`, `reconcile-access`, `propustka.access.ts`, `ACCESS_APPS`/`TEAM`;
   rebirth `propustka.access.ts` as the middleware path-config. Update `architecture.md` + `CLAUDE.md`.
5. **Per-app session cookie via redirect ticket** — for apps NOT under one registrable domain
   (parent-domain cookie is the v1 default).
6. **Durable signing-key provisioning + rotation runbook** (the foundation supports multi-key
   rotation; the ops process is TODO).
