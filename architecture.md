# Propustka — Architecture

Ties together the two specs into a buildable whole:

- `iam-service-spec.md` — the IAM Worker (RPC, D1 model, capabilities, provisioning).
- `admin-ui-spec.md` — the admin SPA.
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
browser (admin) ──▶ Access (admin-only policy) ──▶ Propustka Worker ── D1 (propustka)
                                                     │  • fetch(): admin SPA + /admin/*
                                                     │  • cron: prune auth_log
                                                     │  • RPC (WorkerEntrypoint):
app worker ───────────── env.IAM (ServiceReference) ─┤      authenticate / audit
  (behind its own Access)                            │      redeemCapability / issueCapability
                                                     │
browser (end user) ──▶ Access (app policy) ──▶ App Worker ──┘
                                                     │
browser (anon, share link) ──▶ [Bypass path on App Worker] ─┘  (App calls iam.redeemCapability)
                       └───────────────────────────────────────────────────────────────────────┘
```

Key boundary facts:

- **App ↔ IAM is RPC over a service binding** (`env.IAM`, an oblaka `ServiceReference`).
  Service bindings are worker-to-worker and **do not traverse the Access edge**, so the IAM
  Worker can be fully behind Access (admin policy) for HTTP yet still serve RPC to apps.
- **The IAM Worker's only HTTP surface is the admin** (SPA + `/admin/*`), behind Access +
  an in-Worker `can('iam.admin')` re-check. It exposes **no public HTTP**.
- **Capability redeem is RPC, not an IAM HTTP route.** The public Bypass path lives on the
  _app_ Worker (e.g. `reports.firma.cz/r/<token>`); the app calls `iam.redeemCapability()`
  over the binding. The IAM Worker never needs a public, Access-free path.
- **`can()` / `scopedTo()` run in the app**, in `@propustka/client`, over the permissions
  array returned by one `authenticate()` RPC. No per-check round-trip.

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
  _and_ the `issueCapability()` delegation check in the Worker (core spec: "Wildcard matching
  happens in TypeScript, not SQL"). One implementation, one set of tests.
- **Shared types** — `DomainEvent`, the `permissions[]` entry shape (`{action, projectId,
  source}`), failure-reason unions, the `RoleDef`/`RoleSource` interface, and the **`IamRpc`
  interface** — the four RPC method signatures (`authenticate`/`audit`/`redeemCapability`/
  `issueCapability`) the Worker `implements` and the SDK consumes. Putting the contract here is
  what lets the SDK type `env.IAM` as `Service<IamRpc>` **without depending on the Worker**.
- **`uuidv7()`** — all self-owned ids are UUIDv7 (hard requirement). Implemented **inline, no
  dependency** (`crypto.randomUUID()` is v4; v7 is ~20 lines: ms timestamp + random, time-sortable).
- **Scope helpers** — the three-state contract behind `scopedTo()` / `applyScope()` lives in
  the SDK, but the underlying types are here.

Pure, no Cloudflare deps, no I/O — so it's trivially unit-testable and safe to bundle into
the published SDK. This is the _only_ abstraction we pre-build; everything else stays concrete.

### `@propustka/worker` — the IAM Worker

The deployable. One `WorkerEntrypoint` whose **default export carries both the RPC methods and
`fetch()`**, so apps reach RPC over the binding while browsers reach the admin over HTTP:

```ts
// src/index.ts
export class Propustka extends WorkerEntrypoint<Env> {
  // ── RPC (called by app workers: env.IAM.authenticate(...)) ──
  authenticate(input)      { /* ... */ }
  audit(event)             { /* ... */ }
  redeemCapability(input)  { /* ... */ }
  issueCapability(input)   { /* ... */ }

  // ── HTTP (admin SPA + /admin/*, behind Access) ──
  override fetch(req: Request) { return this.router.handle(req) }
}
export default Propustka

// cron handler (prune auth_log) — see oblaka triggers.crons
export const scheduled = ...   // or a method; wire per CF API
```

Module breakdown (concrete, mirrors opice's `src/` shape):

```
packages/worker/
  oblaka.ts                  # IaC: Worker + D1 + ASSETS + crons + vars/secrets (see below)
  lopata.config.ts           # local CF runtime config (lopata dev)
  wrangler.jsonc             # generated by oblaka — do not hand-edit
  migrations/                # D1 schema (0001_init.sql, ...)
  src/
    index.ts                 # WorkerEntrypoint: RPC methods + fetch + scheduled
    env.ts                   # Env interface — single source of truth for bindings/secrets
    services.ts              # buildServices(env): wires db, cache, jwt, cf-api (opice pattern)
    db.ts                    # D1 data access (principals, grants, audit, capabilities, ...)
    roles.ts                 # ROLES registry + RoleSource impl (code-defined; core spec)
    resolve.ts               # permission resolution: grants ∪ groups ∪ bootstrap, dedupe
    jwt.ts                   # jose JWKS validate; aud → app via ACCESS_APPS
    identity.ts              # get-identity fetch + group→role mapping (users only)
    cache.ts                 # per-isolate principal cache, short TTL, fail-to-D1
    capabilities.ts          # redeem (atomic UPDATE…RETURNING) + issue (delegation rule)
    cfaccess.ts              # Cloudflare Access API client (service-token provisioning)
    admin/
      router.ts              # /admin/* REST; admin gate (can('iam.admin'))
      handlers.ts            # principals/grants/projects/group-mappings/api-keys/...
```

The class **`implements IamRpc`** from `@propustka/core`, so the SDK can type the binding as
`Service<IamRpc>` without importing the Worker at all. The Worker still exports its
**admin-API request/response DTOs** (type-only) for `@propustka/admin-ui` to import — the
opice dashboard pattern (`import type` from the worker, end-to-end typed, no codegen).

### `@propustka/client` — the app SDK (published)

A **normal runtime package** — real classes (`IamClient`, `AuthContext`, `Capability`) and
functions (`applyScope`, `FakeIamClient`), fully defined in the core spec's "Client SDK"
section. Framework-agnostic, runs inside app Workers; **the only package published to npm**.

Depends **only on `@propustka/core`** (a normal runtime dependency: the matcher powers
`can()`/`scopedTo()`; `IamRpc`/`DomainEvent`/permission types come from there). It does **not**
depend on `@propustka/worker`: the constructor takes the service binding typed as
`Service<IamRpc>`, and `authenticate()`/`audit()`/etc. are RPC calls to the _deployed_ Worker
over that binding. The Worker's runtime (D1, jose, the CF Access client) is never imported, so
adopting apps don't bundle any of it — they ship the thin SDK and reach the real Worker through
the binding.

### `@propustka/admin-ui` — the admin SPA

buzola SPA per `admin-ui-spec.md`. Built with Vite to `dist/`, which the Worker serves via its
`ASSETS` binding. Imports the Worker's admin-API types type-only so requests/responses are
typed end to end. Detailed page/IA design lives in its own spec; this doc only places it in the
build graph.

Decided stack (see `admin-ui-spec.md` → Resolved decisions): **SPA served at the Worker root
`/`** while the **JSON API stays at `/admin/*`** (core-spec paths verbatim — `run_worker_first`
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
			run_worker_first: true, // fetch() runs before static: route /admin/* + Access gate
		},
		bindings: {
			DB: new D1Database({
				name: 'propustka',
				migrationsDir: './migrations',
				locationHint: 'weur',
			}),
		},
		vars, // ENVIRONMENT, ACCESS_APPS, TEAM, IAM_BOOTSTRAP_ADMINS, ...
		// secrets (CF_API_TOKEN, CF_ACCOUNT_ID) injected via vars from process.env on stage/prod
	})
})
```

**One D1 (`propustka`)** holds both table groups. The core spec's "keep them separate" is a
_logical_ separation (mutable policy state vs. append-only audit) realized as distinct tables +
retention, not separate databases — internal scale doesn't warrant two D1s. (Additive later if
ever needed.)

**Env & secrets** (`src/env.ts` is the typed source of truth):

| Name                   | Kind       | Purpose                                                     |
| ---------------------- | ---------- | ----------------------------------------------------------- |
| `DB`                   | binding    | D1                                                          |
| `ASSETS`               | binding    | admin SPA static assets                                     |
| `ACCESS_APPS`          | var (JSON) | `{ "<aud>": "<app-id>" }` — JWT audience set + app identity |
| `TEAM`                 | var        | Access team domain (JWKS issuer)                            |
| `IAM_BOOTSTRAP_ADMINS` | var (JSON) | bootstrap admin emails (normally empty)                     |
| `CF_API_TOKEN`         | **secret** | Access service-token provisioning (admin-only)              |
| `CF_ACCOUNT_ID`        | **secret** | account id for the Access API                               |
| `ENVIRONMENT`          | var        | `local` / `stage` / `prod`                                  |

Local provides safe inline values; stage/prod read from `process.env` in `oblaka.ts` and throw
if missing (opice precedent) so we never ship a half-configured deploy.

### How an app Worker wires the binding

In the **app's own** `oblaka.ts`, add a `ServiceReference` to the IAM Worker by name:

```ts
bindings: {
  IAM: new ServiceReference('propustka-worker'),   // env.IAM.authenticate(...) etc.
  // ... app's own DB, etc.
}
```

Then in app code: `const iam = new IamClient(env.IAM, "app-projects")` (core spec usage). In
`wrangler dev`, the app selects `FakeIamClient` by env flag and needs no binding at all.

## Local development (lopata)

Local CF runtime is **lopata** (drop-in for `wrangler dev`, runs on Bun), same as opice:

```
packages/worker/   bunx lopata dev --env local --port <p>     # IAM Worker + D1 locally
packages/admin-ui/ vite                                        # SPA dev server, proxy /admin → worker
```

Caveats specific to IAM:

- **Access doesn't exist locally.** App-side, the `FakeIamClient` covers `wrangler dev` (fixed
  identity, `can()`→true, deny-list for 403 paths) — no Access, no IAM Worker. For exercising
  the _real_ IAM Worker locally, feed fixture JWTs/cookies; full Access integration
  (especially `get-identity`) **must be verified against a real Access-protected host early** —
  the core spec flags this as the one external integration point.
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
# CI provides CLOUDFLARE_ACCOUNT_ID / CLOUDFLARE_API_TOKEN and the app secrets via env.
bunx oblaka oblaka.ts --remote --env stage   # then --env prod
wrangler d1 migrations apply propustka --remote
```

oblaka tracks created-resource ids in a `cf-state` KV namespace (its state store). Secrets
(`CF_API_TOKEN`, `CF_ACCOUNT_ID`, plus `OPICE_*`-style values for stage/prod) come from CI
secrets, never committed.

## Testing strategy (brief)

- **Unit (`bun test`)** on `@propustka/core`: the permission matcher (wildcards, `project.*`
  ⊇ `project.read`), UUIDv7 monotonicity, scope three-state logic. Pure functions, no mocks.
- **Worker unit/integration:** resolution (`grants ∪ groups ∪ bootstrap`, dedupe, source
  tags), the atomic redeem `UPDATE…RETURNING` failure classification, the delegation check,
  fail-closed paths — against a local D1 (lopata) with seeded rows.
- **Contract:** the acceptance criteria in the core spec (1–16) are the integration test
  checklist. The 401/403 distinction, once-shown secret, and group-resolution outage
  (`groupsUnavailable`) each map to a test.
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
