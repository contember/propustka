# Propustka — Architecture

Ties the design into a buildable whole:

- `propustka-native-spec.md` — the current design of record: propustka-native auth (any-OIDC SSO,
  the unified credential primitive, per-app tokens, in-process per-path gates) that replaced
  Cloudflare Access entirely.
- **this doc** — repository layout, package graph, the Worker's internal module structure,
  provisioning with **oblaka**, local dev with **lopata**, environments, and the build/deploy
  pipeline.

Conventions follow our existing OSS Workers projects — primarily **`oss/opice`** (buzola SPA
served by a Worker via the `ASSETS` binding, oblaka provisioning, lopata local dev) and the
**oblaka** IaC DSL.

> Naming: the repo is **propustka**. Internal workspace packages are `@propustka/*`. The
> published client SDK is what the core spec's examples call `@firma/iam-client` — i.e. the
> consuming org scopes it; here it's `@propustka/client`.

## Topology

```
                       ┌───────────────────────────── Cloudflare ─────────────────────────────┐
browser (admin) ──▶ Propustka Worker ── D1 (propustka)
                       │  • fetch(): admin SPA + /admin/* (native px_session/px_ admin gate)
                       │             + /auth/* OIDC login + /.well-known/jwks.json
                       │  • cron: prune auth_log
                       │  • RPC (WorkerEntrypoint):
app worker ── env.IAM (ServiceReference) ─┤   mintToken / mintFromKey / issueKey / issueJwt
                       │                  │   getJwks / audit / listPrincipals / revokeKey
browser (end user) ──▶ App Worker (PropustkaAuth) ──┘     (human: px_session → mintToken → px_token)
                       │
browser (anon, share link px_) ──▶ App Worker SDK ──┘   (SDK resolves the px_ key via iam.mintFromKey)
                       └───────────────────────────────────────────────────────────────────────┘
```

There is **no Cloudflare Access edge** — propustka authenticates everyone itself (OIDC SSO for
humans, `px_` keys / passthrough JWTs for machines) and gates every path in-process via the SDK.

Key boundary facts:

- **App ↔ IAM is RPC over a service binding** (`env.IAM`, an oblaka `ServiceReference`).
  Service bindings are worker-to-worker, so the SDK reaches the IAM Worker (mint, JWKS, audit)
  without any HTTP hop or edge in between.
- **The IAM Worker's HTTP surface is the admin** (SPA + `/admin/*`, gated natively at app
  `propustka` by a `px_session` cookie or a `Bearer px_` admin key + an in-Worker
  `permits(perms, 'iam.admin')` re-check) **plus the OIDC login** (`/auth/login`, `/auth/callback`,
  `/auth/logout`) and `/.well-known/jwks.json`. No CF Access in front of any of it.
- **The SDK enforces per-path gates in-process** (`AppGates`: `public` / `service` / `human`,
  first-match-wins, fail-closed). There is no edge reconcile and no worker gate endpoint — the gate
  declaration is pure SDK config the app ships.
- **Share-link resolution is RPC, not an IAM HTTP route.** A share link is an anonymous `px_`
  credential riding in a URL path/header (e.g. `reports.firma.cz/r/<px_token>`); the app's SDK
  resolves it via `iam.mintFromKey()` over the binding.
- **`can()` / `scopedTo()` run in the app**, in `@propustka/client`, over the permissions baked into
  the locally-verified per-app access token. No per-check round-trip.

## Repository layout

Bun monorepo, mirroring opice/buzola (`bun.lock`, `tsconfig.base.json` + project references,
Biome + dprint).

```
propustka/
  package.json                 # private root; workspaces: ["packages/*"]
  tsconfig.json                # solution: references every package
  tsconfig.base.json           # shared strict compilerOptions (copy from opice)
  biome.json  dprint.json
  bun.lock
  packages/
    core/                      # @propustka/core   — shared pure logic & types (no I/O)
    worker/                    # @propustka/worker  — the IAM Worker (RPC + admin API + cron)
    client/                    # @propustka/client  — the app-facing SDK (published)
    admin-ui/                  # @propustka/admin-ui — buzola SPA, built into worker assets
```

Four packages, each with one job. The dependency graph is acyclic:

```
        ┌──────────────────────────────────────────────────────┐
        │  core   permission matcher · shared types · UUIDv7 ·   │
        │         RoleSource · IamRpc interface · DomainEvent     │
        └──────────────────────────────────────────────────────┘
          ▲ runtime          ▲ runtime            ▲ runtime
   ┌──────┘                  │                    └──────┐
┌────────┐              ┌────────┐                 ┌──────────┐
│ client │              │ worker │◀────────────────│ admin-ui │
└────────┘              └────────┘   type-only     └──────────┘
 IamClient class       implements IamRpc           (worker's admin-API DTOs)
 wraps Service<IamRpc>

# Every edge into `core` is a normal runtime dependency. The only type-only edge is
# admin-ui → worker (for the admin REST DTOs). `client` does NOT depend on `worker`:
# the RPC contract (IamRpc) lives in `core`, so the SDK types the binding as
# Service<IamRpc> and calls the deployed Worker over the service binding at runtime.
```

### `@propustka/core` — the one shared library

The deliberately small shared package — only things that **must not drift** between the
Worker and the SDK:

- **Permission matcher** — wildcard matching (`*`, `prefix.*`) used by both `can()` in the SDK
  _and_ the `issueKey()` delegation check in the Worker (wildcard matching happens in TypeScript,
  not SQL). One implementation, one set of tests. Alongside it,
  `isActionAllowed(pattern, catalog)` — the action-catalog validator the Worker uses to keep
  inline-grant and policy patterns inside an app's declared action set.
- **Shared types** — `DomainEvent`; the `permissions[]` entry shape (`{action, scope, source}`,
  where `scope` is the generic `{ type, value } | null` coordinate, NOT a project id); the
  `Scope` type; the `RoleDef`/`RoleSource` interfaces; the **app-vocabulary types**
  (`AppSchema` = `{ scopes, actions, roles }`, with `AppScopeDef` / `AppActionDef`) an app
  declares in code and reconciles in; the **per-path gate types** (`AppGates`/`GateRule`/`GateKind`)
  an app declares and passes to `PropustkaAuth`; failure-reason unions; and the **`IamRpc`
  interface** — the RPC method signatures (`mintToken`/`mintFromKey`/`issueKey`/`issueJwt`/`getJwks`/
  `audit`/`listPrincipals`/`revokeKey`) the Worker `implements` and the SDK consumes. Putting the
  contract here is what lets the SDK type `env.IAM` as `Service<IamRpc>` **without depending on the
  Worker**.
- **`uuidv7()`** — all self-owned ids are UUIDv7 (hard requirement). Implemented **inline, no
  dependency** (`crypto.randomUUID()` is v4; v7 is ~20 lines: ms timestamp + random, time-sortable).
- **Scope helpers** — `scopedValues()` (the resolution behind `scopedTo(action, dimension)`)
  and the three-state contract behind `applyScope()`; the underlying `Scope` / permission types
  live here too.

Pure, no Cloudflare deps, no I/O — so it's trivially unit-testable and safe to bundle into
the published SDK. This is the _only_ abstraction we pre-build; everything else stays concrete.

### `@propustka/worker` — the IAM Worker

The deployable. One `WorkerEntrypoint` whose **default export carries both the RPC methods and
`fetch()`**, so apps reach RPC over the binding while browsers reach the admin over HTTP:

```ts
// src/index.ts
export class Propustka extends WorkerEntrypoint<Env> {
  // ── RPC (called by app workers: env.IAM.mintToken(...) etc.) ──
  mintToken(input)         { /* ... */ }   // session → signed per-app access token
  mintFromKey(input)       { /* ... */ }   // px_ key → signed per-app access token
  issueKey(input)          { /* ... */ }
  issueJwt(input)          { /* ... */ }
  getJwks()                { /* ... */ }
  audit(event)             { /* ... */ }
  listPrincipals(input)    { /* ... */ }
  revokeKey(input)         { /* ... */ }

  // ── HTTP (admin SPA + /admin/* + OIDC /auth/* + JWKS; native gate) ──
  override fetch(req: Request) { return this.router.handle(req) }
}
export default Propustka

// cron handler (prune auth_log) — see oblaka triggers.crons
export const scheduled = ...   // or a method; wire per CF API
```

There is no `authenticate()` RPC — humans mint a token from their SSO session (`mintToken`),
machines from a `px_` key (`mintFromKey`), and the SDK verifies every subsequent request locally
against the JWKS (`getJwks`). For the management RPCs the Worker resolves the CALLER itself via
`resolveCaller` (verify a forwarded `px_token` against its OWN signing keys, or resolve a `px_` key).

Module breakdown (concrete, mirrors opice's `src/` shape):

```
packages/worker/
  oblaka.ts                  # IaC: Worker + D1 + ASSETS + crons + vars/secrets (see below)
  vozka.config.ts            # vozka deploy surface (folds oblaka into one defineApp)
  lopata.config.ts           # local CF runtime config (lopata dev)
  wrangler.jsonc             # generated by oblaka — do not hand-edit
  migrations/                # D1 schema (0001_init.sql ... 0007_drop_group_access.sql)
  src/
    index.ts                 # WorkerEntrypoint: RPC methods + fetch + scheduled
    env.ts                   # Env interface — single source of truth for bindings/vars/secrets
    services.ts              # buildServices(env): wires db, oidc client, parsed config
    db.ts                    # D1 data access (principals, grants, audit, credentials, sessions, ...)
    roles.ts                 # built-in cross-app `admin=['*']` + RoleSource over the app's DB roles
    resolve.ts               # permission resolution: grants (role or inline) ∪ bootstrap, dedupe
    auth.ts                  # resolveCaller — native caller resolution (px_token verify / px_ key) + local-dev bypass
    signing.ts               # ES256 signer over PROPUSTKA_SIGNING_KEYS: sign + verifyAccessToken + JWKS
    oidc.ts                  # OIDC relying-party client (discovery, code exchange, id_token verify)
    secret.ts                # opaque-secret helpers (generateToken / hashToken) for stored credentials
    tokens.ts                # mintToken (session) + mintFromKey (px_ key) + resolveCredential → access token
    issue.ts                 # issueKey / issueJwt / revokeKey (the unified credential primitive)
    auth/
      routes.ts              # /auth/login + /auth/callback (admission) + /auth/logout
      cookies.ts             # px_session / OIDC-state cookie helpers
    admin/
      router.ts              # /admin/* REST; native admin gate (resolveAdmin → permits('iam.admin')) + CSRF guard
      handlers.ts            # principals/grants/api-keys/share-links/apps (schema reconcile + custom policies)/audit/auth-log
```

The class **`implements IamRpc`** from `@propustka/core`, so the SDK can type the binding as
`Service<IamRpc>` without importing the Worker at all. The Worker still exports its
**admin-API request/response DTOs** (type-only) for `@propustka/admin-ui` to import — the
opice dashboard pattern (`import type` from the worker, end-to-end typed, no codegen).

### `@propustka/client` — the app SDK (published)

A **normal runtime package** — real classes (`IamClient`, `AuthContext`, `PropustkaAuth`) and
functions (`applyScope`, `FakeIamClient`). Framework-agnostic, runs inside app Workers; **the
only package published to npm**.

Depends **only on `@propustka/core`** (a normal runtime dependency: the matcher powers
`can()`/`scopedTo()`; `IamRpc`/`DomainEvent`/the gate + permission types come from there). It does
**not** depend on `@propustka/worker`: `PropustkaAuth`/`IamClient` take the service binding typed as
`Service<IamRpc>`, and `mintToken()`/`audit()`/etc. are RPC calls to the _deployed_ Worker over that
binding. The Worker's runtime (D1, jose signing, the OIDC client) is never imported, so adopting apps
don't bundle any of it — they ship the thin SDK (which does carry `jose` for the local token verify)
and reach the real Worker through the binding.

### `@propustka/admin-ui` — the admin SPA

buzola SPA. Built with Vite to `dist/`, which the Worker serves via its `ASSETS` binding.
Imports the Worker's admin-API types type-only so requests/responses are typed end to end. This
doc places it in the build graph; the live pages are under `packages/admin-ui/src/routes/`.

Decided stack: **SPA served at the Worker root `/`** while the **JSON API stays at `/admin/*`**
(`run_worker_first`
routes `/admin/*` to the API handlers, everything else falls through to the SPA assets);
**data via buzola loaders** (no react-query); **minimal hand-rolled UI** (no component kit).

## Provisioning (oblaka)

`packages/worker/oblaka.ts` defines the whole stack. Shape follows opice's `oblaka.ts`:

```ts
import { D1Database, define, Worker } from 'oblaka-iac'

export default define(({ env }) => {
	// local: inline dev values; stage/prod: read secrets from process.env (CI sets them),
	// throw loudly if missing — same pattern as opice's envVarsFor().
	const vars = buildVars(env)

	return new Worker({
		dir: '.',
		name: 'propustka-worker', // ← app workers reference this name
		main: './src/index.ts',
		compatibility_flags: ['nodejs_compat_v2'],
		compatibility_date: '2025-10-01',
		observability: { enabled: true },
		triggers: { crons: ['0 3 * * *'] }, // prune auth_log (retention: weeks)
		assets: {
			directory: '../admin-ui/dist',
			binding: 'ASSETS',
			not_found_handling: 'single-page-application', // SPA deep links → index.html
			run_worker_first: true, // fetch() runs before static: route /admin/* + /auth/* + native gate
		},
		bindings: {
			DB: new D1Database({
				name: 'propustka',
				migrationsDir: './migrations',
				locationHint: 'weur',
			}),
		},
		vars, // ENVIRONMENT, ISSUER, HUMAN_EMAIL_DOMAINS, OIDC_*, IAM_BOOTSTRAP_ADMINS, ...
		// PROPUSTKA_SIGNING_KEYS / PROPUSTKA_OIDC_CLIENT_SECRET are NOT vars (oblaka has no secrets
		// field): they are provisioned out-of-band as Worker secrets — `wrangler secret put` on
		// stage/prod, `.dev.vars` locally — so they never land in the generated wrangler.jsonc.
	})
})
```

> A `vozka.config.ts` mirrors this same resource graph for the vozka deploy engine; `oblaka.ts`
> stays as the local-dev shim. Both build the identical Worker — vars come from per-env config.

**One D1 (`propustka`)** holds both table groups. The core spec's "keep them separate" is a
_logical_ separation (mutable policy state vs. append-only audit) realized as distinct tables +
retention, not separate databases — internal scale doesn't warrant two D1s. (Additive later if
ever needed.)

**Env & secrets** (`src/env.ts` is the typed source of truth):

| Name                          | Kind       | Purpose                                                                 |
| ----------------------------- | ---------- | ----------------------------------------------------------------------- |
| `DB`                          | binding    | D1                                                                      |
| `ASSETS`                      | binding    | admin SPA static assets                                                 |
| `ISSUER`                      | var        | propustka's own origin (`PROPUSTKA_HOSTNAME`) — token `iss` + OIDC base |
| `HUMAN_EMAIL_DOMAINS`         | var (JSON) | login-admission domains (`*` = admit-all)                               |
| `HUMAN_EMAILS`                | var (JSON) | login-admission emails, additive (`*` = admit-all)                      |
| `IAM_BOOTSTRAP_ADMINS`        | var (JSON) | bootstrap admin emails (normally empty)                                 |
| `OIDC_ISSUER`                 | var        | OIDC provider issuer (discovery base)                                   |
| `OIDC_CLIENT_ID`              | var        | OIDC client id (public)                                                 |
| `OIDC_SCOPES`                 | var        | space-separated scopes; empty → `openid email profile`                  |
| `OIDC_REQUIRE_VERIFIED_EMAIL` | var        | `'false'` to accept logins lacking `email_verified`; else required      |
| `SESSION_COOKIE_DOMAIN`       | var        | `Domain` for `px_session` (e.g. `.example.com`); empty → host-only      |
| `PROPUSTKA_SIGNING_KEYS`      | **secret** | JSON array of EC P-256 private JWKs — signs the per-app access tokens   |
| `OIDC_CLIENT_SECRET`          | **secret** | OIDC code-exchange credential                                           |
| `ENVIRONMENT`                 | var        | `local` / `stage` / `prod`                                              |

Local provides safe inline values; stage/prod read from `process.env` in `oblaka.ts` and throw
if missing (opice precedent) so we never ship a half-configured deploy. The two secrets are never
placed in `vars` — `wrangler secret put` remotely, `.dev.vars` locally.

### How an app Worker wires the binding

In the **app's own** `oblaka.ts`, add a `ServiceReference` to the IAM Worker by name:

```ts
bindings: {
  IAM: new ServiceReference('propustka-worker'),   // env.IAM.authenticate(...) etc.
  // ... app's own DB, etc.
}
```

Then in app code the app constructs `new PropustkaAuth(env.IAM, "app-projects", { issuer, gates })`
as its front door (`IamClient` is the management-RPC client). In `wrangler dev` the local-dev bypass
on the IAM Worker resolves a fixed admin, so the binding still works against lopata; `FakeIamClient`
stands in for the management RPCs where no Worker is wired.

### Per-path gates (in-process) + provisioning (`scripts/`)

There is **no edge to reconcile**. Each app declares its per-path gates as a typed `AppGates`
(`@propustka/core`) — an ordered, first-match-wins list of `public` / `service` / `human` rules
(e.g. `examples/app/propustka.gates.ts`) — and passes it to `PropustkaAuth`. The SDK enforces them
in-process, fail-closed; nothing is pushed to propustka.

> **Who may log in as a HUMAN is owned CENTRALLY by propustka**, not per app: the
> `HUMAN_EMAIL_DOMAINS` / `HUMAN_EMAILS` Worker vars (deploy vars `PROPUSTKA_HUMAN_EMAIL_DOMAINS` /
> `PROPUSTKA_HUMAN_EMAILS`) are the login-admission allowlist applied at `/auth/callback` for EVERY
> app — a `*` entry = admit-all; otherwise an exact email or matching domain. An app's gates say only
> THAT a path is human-gated; per-path authorization is the app's own `can()`. Apps own their path
> shape (public vs gated) + their authz; propustka owns who-is-a-valid-human — cleanly split.

The remaining operator scripts reconcile state that lives outside the Worker's own deploy. They are
run by hand (the operator holds the credentials; nothing is committed), and support `--dry-run`.
Both authenticate to `/admin/*` with a propustka-issued `px_` admin key
(`PROPUSTKA_ADMIN_KEY`, sent as `Authorization: Bearer`); a local run uses the dev bypass instead.

- **`scripts/provision-key.ts` — mint a per-app PROVISIONING KEY.** Thin wrapper over
  `POST /admin/api-keys` (`type: 'service'`): it creates a NATIVE service principal (`external_id`
  NULL, resolved by its `px_` key — no CF client_id/secret) + a grant + a bound opaque `px_` key, in
  one. Each downstream app gets one; the returned `apiKey` becomes that app's CI `PROPUSTKA_ADMIN_KEY`
  for the self-reconcile path below. Currently granted the built-in cross-app `admin` role (the same
  privilege contember prod uses today); least-privilege per-app reconcile authz is a tracked follow-up.

- **`scripts/provision-schemas.ts` — each app's authz vocabulary.** Authz is no longer
  Propustka-owned: **each app owns its scope dimensions, action catalog, and roles and declares
  them in its own code** as a typed `AppSchema` (e.g. `examples/app/propustka.schema.ts`,
  imported from `@propustka/core`). This script `PUT`s each declared schema to the idempotent
  `PUT /admin/apps/:app/schema` endpoint (via `reconcileSchema` in `@propustka/client`), so the
  Worker's DB (`app_scopes`, `app_actions`, origin=`app` `roles`) always mirrors what the app
  actually checks at runtime via `can()` / `scopedTo()`. An app's FIRST reconcile is what REGISTERS
  it — `db.listKnownApps()` then surfaces its id across the schema tables. Reconcile is idempotent:
  it upserts the declared rows, deletes app-origin rows the app removed, and **never touches
  origin=`custom` policies** (admin-composed in the UI). The built-in cross-app `admin=['*']` role
  stays in Worker code (`roles.ts`), not in any app's schema.

The model these reconcile into: a grant is scoped to a generic, flat `(scope_type, scope_value)`
coordinate — the dimension name plus an **opaque, app-owned value Propustka never interprets**
(both NULL = global). Dimensions are flat and independent (no hierarchy); the old
Propustka-owned `projects` table is gone. Permissions are AWS-IAM-style and additive-allow:
a grant carries **either** a named role/policy (`role_key`) **or** an inline action set
(`permissions`) — exactly one — and inline/policy patterns are validated against the app's
action catalog.

## Local development (lopata)

Local CF runtime is **lopata** (drop-in for `wrangler dev`, runs on Bun), same as opice:

```
packages/worker/   bunx lopata dev --env local --port <p>     # IAM Worker + D1 locally
packages/admin-ui/ vite                                        # SPA dev server, proxy /admin → worker
```

Caveats specific to IAM:

- **No real OIDC provider locally.** The IAM Worker's local-dev bypass (`ENVIRONMENT=local` + empty
  `PROPUSTKA_SIGNING_KEYS` + no credential → a fixed `local-dev-admin`) lets the example app and the
  admin scripts work against lopata over the binding with no login. `FakeIamClient` covers the
  management RPCs where no Worker is wired. The only leg that needs a real upstream is the OIDC login
  flow (`/auth/login` → IdP → `/auth/callback`) — **verify it against a real provider host early.**
- D1 migrations apply locally and remotely via wrangler (opice scripts):
  `wrangler d1 migrations apply propustka --local` / `--remote`.
- `wrangler types` (or `@cloudflare/workers-types`) regenerates binding types after oblaka
  changes the shape.

## Build & typecheck

- **Root:** `tsc --build` over project references (`bun run typecheck`), Biome lint, dprint
  format — identical to opice/buzola.
- **admin-ui:** `buzola` codegen (`bun run gen` → `src/buzola.gen.ts`) **must run before**
  typecheck/build (the shipped buzola CLI is Node and can't load TSX routes — run gen via Bun,
  per opice's dashboard CLAUDE.md), then `vite build` → `dist/`.
- **worker:** consumes `../admin-ui/dist` via the `ASSETS` binding, so admin-ui builds first in
  CI ordering.

## Deploy & environments

Three envs (`local` / `stage` / `prod`), matching opice. Deploy is oblaka against the real
account:

```bash
# CI provides CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN and the app vars/secrets via env.
bunx oblaka oblaka.ts --remote --env stage   # then --env prod
wrangler d1 migrations apply propustka --remote
```

oblaka tracks created-resource ids in a `cf-state` KV namespace (its state store).
`PROPUSTKA_SIGNING_KEYS` and `OIDC_CLIENT_SECRET` are Worker **secrets**, not vars — oblaka can't
express secrets, so they are never placed in `vars`/`wrangler.jsonc`. Provision them out-of-band:
`wrangler secret put PROPUSTKA_SIGNING_KEYS` / `wrangler secret put PROPUSTKA_OIDC_CLIENT_SECRET` on
stage/prod, and `packages/worker/.dev.vars` (gitignored; copy `.dev.vars.example`) locally. They
come from CI secrets, never committed.

## Testing strategy (brief)

- **Unit (`bun test`)** on `@propustka/core`: the permission matcher (wildcards, `project.*`
  ⊇ `project.read`), UUIDv7 monotonicity, scope three-state logic. Pure functions, no mocks.
- **Worker unit/integration:** resolution (`grants ∪ bootstrap`, dedupe, source tags), native
  caller resolution (`resolveCaller`: `px_token` verify / `px_` key / anonymous-reject / local-dev
  bypass), the `/admin` native gate (session admin, bearer admin, non-admin 403, CSRF), the
  `/auth/callback` admission check (`*` / domain / email / bootstrap / refused), the delegation
  check, fail-closed paths — against a local D1 (lopata) with seeded rows.
- **Contract:** the acceptance criteria in the core spec are the integration test checklist. The
  401/403 distinction and the once-shown secret each map to a test.
- **Admin UI:** thin — it's dumb about authz (server re-checks). A couple of opice-style
  browser smoke tests for the critical flows (grant a role, provision an API key, view audit)
  are enough at internal scale.

## What we are explicitly NOT building (architecture-level)

Inherits the core spec's out-of-scope list, plus:

- No separate audit D1, no Pipelines/R2 spooling (single D1; R2 only "if it ever grows", which
  it won't at internal scale).
- No second app Worker in this repo — propustka ships the IAM Worker + SDK + admin only; apps
  live in their own repos and depend on `@propustka/client` + a `ServiceReference`.
- No custom key format, no per-app secret auth, no runtime role store (all per core spec).
- No `@propustka/core` over-reach: it holds only logic that must agree across packages; resist
  growing it into a junk-drawer.

```
```
