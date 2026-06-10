# Propustka

Internal **IAM & audit service** for apps running on Cloudflare Workers. Authentication is
handled at the edge by **Cloudflare Access**; Propustka owns everything after that —
authorization (RBAC scoped to projects), auth logging, domain-event audit, capability tokens,
and a small admin UI. Apps call it through a thin SDK over a **service binding** and just do
`authenticate()` + `can()` + `audit()`.

Division of responsibility:

| Layer                                  | Owns                                                                        |
| -------------------------------------- | --------------------------------------------------------------------------- |
| **Cloudflare Access** (not built here) | authentication (who you are) + coarse edge gate                             |
| **Propustka Worker**                   | authorization (RBAC), auth log, audit ingest, capabilities, request context |
| **Apps**                               | emit domain audit events; call `authenticate()` / `can()` / `audit()`       |

Design docs: [`iam-service-spec.md`](./iam-service-spec.md) ·
[`admin-ui-spec.md`](./admin-ui-spec.md) · [`architecture.md`](./architecture.md).

## Packages

Bun monorepo (`packages/*`). Acyclic graph: everything depends on `core`; `client` and
`admin-ui` never depend on each other.

| Package                   | What it is                                                                                                                                                                                                                                      |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@propustka/core`**     | Pure shared lib: action matcher (`*` / `prefix.*` / exact), `permits()`, `uuidv7()`, shared types, and the **`IamRpc`** contract the worker implements and the SDK consumes. No I/O, no deps.                                                   |
| **`@propustka/worker`**   | The IAM Worker. `WorkerEntrypoint` implementing the RPC surface + the `/admin/*` REST API + the admin SPA assets + a cron that prunes the auth log. D1 datastore, `jose` JWT validation, Cloudflare Access provisioning, `oblaka` provisioning. |
| **`@propustka/client`**   | The app-facing SDK (the only published package): `IamClient`, `AuthContext`, `Capability`, `applyScope`, and `FakeIamClient` for `wrangler dev`. Depends only on `core`.                                                                        |
| **`@propustka/admin-ui`** | buzola + React admin SPA served by the worker at `/`. Manages principals, grants, projects, group→role mappings, API keys, capabilities; views the audit + auth logs.                                                                           |

## Quick start

Requires **[Bun](https://bun.sh)** (≥ 1.3).

```bash
bun install
bun run typecheck     # tsc --noEmit across all packages
bun test              # 97 tests
bun run lint          # biome
bun run format        # dprint
```

## Local development

Local Cloudflare runtime is **[lopata](https://github.com/contember/lopata)** (a `wrangler dev`
drop-in on Bun). Bindings (D1, static assets) are backed by SQLite + files under `.lopata/`.

```bash
cd packages/admin-ui && bun run build        # produce admin-ui/dist (the worker serves it)
cd ../worker
bun run oblaka                               # generate wrangler.jsonc from oblaka.ts
bunx lopata d1 migrations apply propustka    # apply the schema to the local D1
bun run dev                                  # lopata dev on http://127.0.0.1:18191
```

For the admin UI with hot reload, run the worker (above) and in another shell:

```bash
cd packages/admin-ui && bun run dev          # vite on http://127.0.0.1:18192, proxies /admin → :18191
```

**What works locally without Access:** the SPA is served (`GET /` and deep links like
`/principals` → `index.html`), and the JSON API gates correctly — a request with no Access JWT
returns `401 {"error":"missing_token"}`. Smoke-verified:

```
GET /              → 200 (SPA)
GET /principals    → 200 (SPA deep-link fallback)
GET /admin/me      → 401 {"error":"missing_token"}
GET /admin/roles   → 401 {"error":"missing_token"}
```

**What needs real Cloudflare Access** (cannot be exercised locally): validating a real Access
JWT, resolving IdP group membership via `get-identity`, and the service-token provisioning
flow. See _Status_ below.

## Using the SDK in an app

In the **app's** `oblaka.ts`, bind the IAM Worker by name:

```ts
import { ServiceReference } from 'oblaka-iac'
// ...
bindings: {
  IAM: new ServiceReference('propustka-worker'),
}
```

In app code:

```ts
import { applyScope, FakeIamClient, IamClient } from '@propustka/client'

const iam = env.DEV
	? new FakeIamClient({ deny: ['project.settings.update'] }) // wrangler dev: no Access, no IAM Worker
	: new IamClient(env.IAM, 'app-projects')

const auth = await iam.authenticate(req)
if (!auth.ok) return new Response(auth.reason, { status: auth.status }) // 401 or 403

if (!auth.can('project.settings.update', { project: id })) {
	return new Response('forbidden', { status: 403 })
}

// list filtering by scope (three-state: all / some / none)
const scope = auth.scopedTo('project.read')
const projects = applyScope(scope, {
	all: () => db.listAllProjects(),
	some: (ids) => db.listProjects({ ids }), // WHERE id IN (...)
	none: () => [],
})

ctx.waitUntil(
	auth.audit({
		action: 'project.settings.update',
		resourceType: 'project',
		resourceId: id,
		diff,
	}),
)
```

## Deploy

```bash
# secrets (CF_API_TOKEN, CF_ACCOUNT_ID, per-env ACCESS_APPS/TEAM/IAM_BOOTSTRAP_ADMINS)
# are read from the environment by oblaka.ts on stage/prod.
cd packages/admin-ui && bun run build
cd ../worker
bunx oblaka oblaka.ts --remote --env stage         # then --env prod
wrangler d1 migrations apply propustka --remote
```

The first admin is bootstrapped statelessly: set `IAM_BOOTSTRAP_ADMINS` (JSON array of emails);
those users resolve to global `admin` until removed from the env var.

## Status

Implemented and verified (typecheck, 97 unit tests, admin-ui build, `oblaka` config gen, a local
`lopata` HTTP smoke, and the app↔IAM RPC path via [`examples/app`](./examples/app)). Two
integration points depend on a live Cloudflare/Access environment and are **implemented to spec
but not yet verified against real infrastructure**:

1. **`get-identity`** group resolution — must be checked against a real Access-protected host.
2. **Service-token provisioning** — the mint/principal/grant flow is implemented; adding the
   token to the app's _Service Auth policy_ is left **manual for v1** (`policyInclusion:
   'manual'`) pending confirmation that the Access policy API supports it.
