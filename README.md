# Propustka

Internal **IAM & audit service** for apps running on Cloudflare Workers. Authentication is
handled at the edge by **Cloudflare Access**; Propustka owns everything after that —
authorization (AWS-IAM-style policies over generic, app-owned scope dimensions), auth logging,
domain-event audit, capability tokens, and a small admin UI. Each app declares its own authz
vocabulary (scope dimensions, action catalog, roles) in code and reconciles it in. Apps call
Propustka through a thin SDK over a **service binding** and just do
`authenticate()` + `can()` + `audit()`.

Division of responsibility:

| Layer                                  | Owns                                                                                                  |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| **Cloudflare Access** (not built here) | authentication (who you are) + coarse edge gate                                                       |
| **Propustka Worker**                   | authorization (policies over app-owned scopes), auth log, audit ingest, capabilities, request context |
| **Apps**                               | emit domain audit events; call `authenticate()` / `can()` / `audit()`                                 |

Design docs: [`iam-service-spec.md`](./iam-service-spec.md) ·
[`admin-ui-spec.md`](./admin-ui-spec.md) · [`architecture.md`](./architecture.md).

## Packages

Bun monorepo (`packages/*`). Acyclic graph: everything depends on `core`; `client` and
`admin-ui` never depend on each other.

| Package                   | What it is                                                                                                                                                                                                                                                                                            |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@propustka/core`**     | Pure shared lib: action matcher (`*` / `prefix.*` / exact), `permits()`, `uuidv7()`, shared types, and the **`IamRpc`** contract the worker implements and the SDK consumes. No I/O, no deps.                                                                                                         |
| **`@propustka/worker`**   | The IAM Worker. `WorkerEntrypoint` implementing the RPC surface + the `/admin/*` REST API + the admin SPA assets + a cron that prunes the auth log. D1 datastore, `jose` JWT validation, Cloudflare Access provisioning, `oblaka` provisioning.                                                       |
| **`@propustka/client`**   | The app-facing SDK (the only published package): `IamClient`, `AuthContext`, `Capability`, `applyScope`, and `FakeIamClient` for `wrangler dev`. Depends only on `core`.                                                                                                                              |
| **`@propustka/admin-ui`** | buzola + React admin SPA served by the worker at `/`. Manages principals, grants (named role or inline action set, over generic scope dimensions), custom policies, group→role mappings, API keys, capabilities; inspects each app's reconciled schema and role catalog; views the audit + auth logs. |

## Quick start

Requires **[Bun](https://bun.sh)** (≥ 1.3).

```bash
bun install
bun run typecheck     # tsc --noEmit across all packages
bun test              # 203 tests
bun run lint          # biome
bun run format        # dprint
```

## Local development

Local Cloudflare runtime is **[lopata](https://github.com/contember/lopata)** (a `wrangler dev`
drop-in on Bun). Bindings (D1, static assets) are backed by SQLite + files under `.lopata/`.

### Click through the admin demo

```bash
cd packages/admin-ui && bun run build                  # build the admin SPA the worker serves
cd ../worker && bun run oblaka                          # generate the worker's wrangler.jsonc
cp .dev.vars.example .dev.vars                          # local secret placeholders (gitignored)
(cd ../../examples/app && bun run oblaka)               # generate the example app's wrangler.jsonc
bunx lopata d1 migrations apply propustka               # create the local D1 schema
bunx lopata d1 execute propustka --file seed.dev.sql    # load sample data (optional, but populates the UI)
bun run dev                                             # http://127.0.0.1:18191
```

Open **http://127.0.0.1:18191** — the admin UI, fully clickable. There is no Cloudflare Access
locally, so the worker runs a **dev bypass**: when `ENVIRONMENT=local` and no Access JWT is
present it resolves a fixed `local-dev-admin` global admin (see `src/auth.ts`). Strictly local —
a real token still validates normally, so stage/prod never reach this branch.

`packages/worker`'s `lopata.config.ts` also runs the [example app](./examples/app) as an
auxiliary worker at **`/demo`**, so the example's audit writes land in the same local D1 the
admin UI reads:

```bash
curl http://127.0.0.1:18191/demo     # the example authenticates + emits an `example.viewed` audit event
```

…then open the admin **Audit** page (or `GET /admin/audit?action=example.viewed`) to watch the
records appear — the app → IAM `audit()` path over the service binding, end to end.

The example app also **owns its authz vocabulary** — scope dimensions, an action catalog, and
roles — declared in code in [`examples/app/propustka.schema.ts`](./examples/app/propustka.schema.ts)
as a typed `AppSchema`. Reconcile it into Propustka (Access-as-code, authz edition) via the
idempotent `PUT /admin/apps/:app/schema` endpoint:

```bash
cd examples/app
bun run provision-schema -- --dry-run                          # print the intended reconcile
PROPUSTKA_URL=http://127.0.0.1:18191 bun run provision-schema  # push it (local dev bypass → no auth)
```

so the admin UI's role / scope / action pickers offer this app's real vocabulary. See
[`examples/app/README.md`](./examples/app/README.md) for the full walkthrough.

For the admin UI with hot reload, run the worker as above and in another shell:

```bash
cd packages/admin-ui && bun run dev  # vite on http://127.0.0.1:18192, proxies /admin → :18191
```

**What still needs real Cloudflare Access** (cannot be exercised locally): validating a real
Access JWT, resolving IdP group membership via `get-identity`, and service-token provisioning.
See _Status_ below.

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

// can(action, scope?) — scope is a flat { type, value } coordinate the app owns;
// omit it to require a global permission. `project` here is one declared dimension.
if (!auth.can('project.settings.update', { type: 'project', value: id })) {
	return new Response('forbidden', { status: 403 })
}

// list filtering by scope (three-state: all / some / none).
// scopedTo(action, dimension) — the dimension is required; values are this app's
// opaque scope values for that dimension.
const scope = auth.scopedTo('project.read', 'project')
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
# Vars (per-env ACCESS_APPS / TEAM / IAM_BOOTSTRAP_ADMINS) are read from the environment
# by oblaka.ts on stage/prod. CF_API_TOKEN / CF_ACCOUNT_ID are Worker secrets (oblaka has
# no secrets field) — provisioned out-of-band with `wrangler secret put`, never as vars.
cd packages/admin-ui && bun run build
cd ../worker
bunx oblaka oblaka.ts --remote --env stage         # then --env prod
wrangler secret put CF_API_TOKEN                    # and CF_ACCOUNT_ID, per deployed env
wrangler d1 migrations apply propustka --remote
```

The first admin is bootstrapped statelessly: set `IAM_BOOTSTRAP_ADMINS` (JSON array of emails);
those users resolve to global `admin` until removed from the env var.

## Status

Implemented and verified (typecheck, 203 unit tests, admin-ui build, `oblaka` config gen, a local
`lopata` HTTP smoke, and the app↔IAM RPC path via [`examples/app`](./examples/app)). Two
integration points depend on a live Cloudflare/Access environment and are **implemented to spec
but not yet verified against real infrastructure**:

1. **`get-identity`** group resolution — must be checked against a real Access-protected host.
2. **Service-token provisioning** — the mint/principal/grant flow is implemented; adding the
   token to the app's _Service Auth policy_ is left **manual for v1** (`policyInclusion:
   'manual'`) pending confirmation that the Access policy API supports it.
