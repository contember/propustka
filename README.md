# Propustka

Internal **IAM & audit service** for apps running on Cloudflare Workers. Propustka owns the whole
auth stack: **authentication** (its own OIDC SSO — any provider — plus opaque `px_` keys and
passthrough JWTs for machines), **authorization** (AWS-IAM-style policies over generic, app-owned
scope dimensions), auth logging, domain-event audit, opaque credentials (API keys / share links),
and a small admin UI. Each app declares its own authz vocabulary (scope dimensions, action catalog,
roles) in code and reconciles it in, and declares its own per-path gates (`public` / `service` /
`human`) enforced in-process by a thin SDK. Apps call Propustka through that SDK over a **service
binding** and just do `authenticate()` + `can()` + `audit()`. There is **no Cloudflare Access** —
propustka replaced it.

Division of responsibility:

| Layer                | Owns                                                                                                                                       |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| **Propustka Worker** | authentication (OIDC SSO, `px_` keys), authorization (policies over app-owned scopes), token issuance, auth log, audit ingest, credentials |
| **Apps (SDK)**       | per-path gating (`AppGates`), local token verify, `can()` / `scopedTo()`, emit domain audit events                                         |

Design docs: [`propustka-native-spec.md`](./propustka-native-spec.md) (the auth model — design of
record) · [`architecture.md`](./architecture.md).

## Packages

Bun monorepo (`packages/*`). Acyclic graph: everything depends on `core`; `client` and
`admin-ui` never depend on each other.

| Package                   | What it is                                                                                                                                                                                                                                                                                                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`@propustka/core`**     | Pure shared lib: action matcher (`*` / `prefix.*` / exact), `permits()`, `uuidv7()`, the access-token build/parse, the per-path gate types (`AppGates`), shared types, and the **`IamRpc`** contract the worker implements and the SDK consumes. No I/O, no deps.                                                                                             |
| **`@propustka/worker`**   | The IAM Worker. `WorkerEntrypoint` implementing the RPC surface (`mintToken` / `mintFromKey` / `issueKey` / `issueJwt` / `getJwks` / `audit` / `listPrincipals` / `revokeKey`) + the `/admin/*` REST API + the OIDC `/auth/*` login flow + the admin SPA assets + a cron that prunes the auth log. D1 datastore, `jose` token signing, `oblaka` provisioning. |
| **`@propustka/client`**   | The app-facing SDK (the only published package): `PropustkaAuth` (the per-path gate middleware), `IamClient` (management RPCs), `AuthContext`, `applyScope`, `reconcileSchema`, and `FakeIamClient` for `wrangler dev`. Depends only on `core`.                                                                                                               |
| **`@propustka/admin-ui`** | buzola + React admin SPA served by the worker at `/`. Manages principals, grants (named role or inline action set, over generic scope dimensions), custom policies, API keys, share links; inspects each app's reconciled schema and role catalog; views the audit + auth logs.                                                                               |

## Quick start

Requires **[Bun](https://bun.sh)** (≥ 1.3).

```bash
bun install
bun run typecheck     # tsc --noEmit across all packages
bun test              # 253 tests
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

Open **http://127.0.0.1:18191** — the admin UI, fully clickable. There is no real OIDC provider
locally, so the worker runs a **dev bypass**: when `ENVIRONMENT=local`, no `PROPUSTKA_SIGNING_KEYS`
is configured, and no credential is presented, it resolves a fixed `local-dev-admin` global admin
(see `resolveCaller` / `resolveAdmin` in `src/auth.ts` + `src/admin/router.ts`). Strictly local — a
real deploy always provisions signing keys, so stage/prod never reach this branch.

`packages/worker`'s `lopata.config.ts` also runs the [example app](./examples/app) as an
auxiliary worker at **`/demo`**, so the example's audit writes land in the same local D1 the
admin UI reads:

```bash
curl http://127.0.0.1:18191/demo     # the example authenticates + emits an `example.view` audit event
```

…then open the admin **Audit** page (or `GET /admin/audit?action=example.view`) to watch the
records appear — the app → IAM path over the service binding, end to end.

The example app also **owns its authz vocabulary** — scope dimensions, an action catalog, and
roles — declared in code in [`examples/app/propustka.schema.ts`](./examples/app/propustka.schema.ts)
as a typed `AppSchema`. Reconcile it into Propustka via the idempotent `PUT /admin/apps/:app/schema`
endpoint (the first reconcile registers the app):

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

Everything exercises locally — the OIDC login flow is the only path that needs a real upstream IdP
(`PROPUSTKA_OIDC_ISSUER` discovery + a code exchange), so the human-login leg is verified against a
real provider host, not lopata. See _Status_ below.

## Using the SDK in an app

In the **app's** `oblaka.ts`, bind the IAM Worker by name:

```ts
import { ServiceReference } from 'oblaka-iac'
// ...
bindings: {
  IAM: new ServiceReference('propustka-worker'),
}
```

The app declares its **per-path gates** in code — an ordered, first-match-wins list of `public` /
`service` / `human` rules enforced in-process (the native successor to the CF Access edge):

```ts
import type { AppGates } from '@propustka/client'

export const gates: AppGates = {
	rules: [
		{ path: '/public/*', kind: 'public' }, // no credential
		{ path: '/*', kind: 'service' }, // a px_ key (Bearer) or passthrough JWT
		{ path: '/*', kind: 'human' }, // else a logged-in human (px_session) — 302s to /auth/login on a miss
	],
}
```

In app code, `PropustkaAuth` is the whole front door — it matches the gate, resolves the credential,
and verifies a short-lived per-app permission token **locally** (no per-request RPC):

```ts
import { PropustkaAuth } from '@propustka/client'
import { gates } from './gates'

const auth = new PropustkaAuth(env.IAM, 'app-projects', {
	issuer: env.PROPUSTKA_ISSUER,
	gates,
})

const result = await auth.authenticate(req)
if (!result.ok) {
	// a human-gated miss carries a loginUrl (bounce the browser); anything else is a flat status.
	if (result.loginUrl !== undefined) {
		return Response.redirect(result.loginUrl, 302)
	}
	return new Response(result.reason, { status: result.status }) // 401 or 403
}
const ctx = result.context

// can(action, scope?) — scope is a flat { type, value } coordinate the app owns;
// omit it to require a global permission. `project` here is one declared dimension.
if (!ctx.can('project.settings.update', { type: 'project', value: id })) {
	return new Response('forbidden', { status: 403 })
}

// list filtering by scope (three-state: all / some / none).
// scopedTo(action, dimension) — the dimension is required; values are this app's
// opaque scope values for that dimension.
const scope = ctx.scopedTo('project.read', 'project')
const projects = applyScope(scope, {
	all: () => db.listAllProjects(),
	some: (ids) => db.listProjects({ ids }), // WHERE id IN (...)
	none: () => [],
})

ctx.waitUntil(
	ctx.audit({
		action: 'project.settings.update',
		resourceType: 'project',
		resourceId: id,
		diff,
	}),
)

const response = Response.json(body)
// when the token was just (re)minted, persist it so the next request hits the local fast path.
if (result.setCookie) response.headers.append('Set-Cookie', result.setCookie)
return response
```

`IamClient` (also exported) carries the **management** RPCs — `issueKey` / `issueJwt` / `revokeKey` /
`listPrincipals`; `FakeIamClient` stands in for it under `wrangler dev`.

## Deploy

Deploys run through CI (see [`CLAUDE.md`](./CLAUDE.md)). The shape:

```bash
# Vars (PROPUSTKA_HOSTNAME / PROPUSTKA_HUMAN_EMAIL_DOMAINS / PROPUSTKA_OIDC_* / IAM_BOOTSTRAP_ADMINS)
# are read from the environment by oblaka.ts on stage/prod. The signing keys + OIDC client secret are
# Worker secrets (oblaka has no secrets field) — provisioned out-of-band, never as vars.
cd packages/admin-ui && bun run build
cd ../worker
bunx oblaka oblaka.ts --remote --env stage              # then --env prod
wrangler secret put PROPUSTKA_SIGNING_KEYS              # and PROPUSTKA_OIDC_CLIENT_SECRET, per env
wrangler d1 migrations apply propustka --remote
```

The first admin is bootstrapped statelessly: set `IAM_BOOTSTRAP_ADMINS` (JSON array of emails);
those users are always admitted at login and resolve to global `admin` until removed from the env var.

## Status

Implemented and verified (typecheck, 253 unit tests, admin-ui build, `oblaka` config gen, a local
`lopata` HTTP smoke, and the app↔IAM path via [`examples/app`](./examples/app)). One leg depends on a
live OIDC provider and is **implemented to spec but not yet verified against a real IdP**:

1. **The OIDC login flow** (`/auth/login` → IdP → `/auth/callback`) — discovery + the code exchange
   must be checked against a real provider (Google/Auth0/Okta/Keycloak/Entra).

Machine identities are fully native: `issueKey({ service })` mints a native service principal + `px_`
credential, resolved via `mintFromKey` — no Cloudflare Access anywhere in the path.
