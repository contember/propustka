// propustka's deploy surface for VOZKA — folds `oblaka.ts` into ONE `vozka-config` `defineApp`. vozka's
// engine loads this to deploy propustka itself: materialize the resource graph (provision via oblaka) and
// run the pipeline. `oblaka.ts` stays as the local-dev shim (imports `buildPropustkaWorker`). propustka
// gates its OWN /admin + /auth surface natively now — there is no Cloudflare Access front door to reconcile.
//
// propustka is config-heavy: its non-secret deploy vars (HUMAN_* / OIDC_*) are environment/account-specific
// and live in vozka's per-app-env registry, declared in `pipeline.vars` and injected into `process.env`
// before `resources()` runs (the SAME `process.env` reads the old `oblaka.ts` did). The real secrets are
// the native-auth ones — `PROPUSTKA_SIGNING_KEYS` + `PROPUSTKA_OIDC_CLIENT_SECRET` (`pipeline.secrets`,
// vault → `wrangler secret put`). The Custom Domain route comes from `ctx.domain` (≙ PROPUSTKA_HOSTNAME).

import type { AppSchema, ResourceContext } from 'vozka-config'
import { D1Database, defineApp, Worker } from 'vozka-config'

// Stable app id — the legacy `propustka-state` oblaka namespace prefix, so the first vozka deploy
// CONTINUES existing cf-state.
const PROPUSTKA_APP_ID = 'propustka'

/** The non-secret deploy vars propustka REQUIRES off-local (validated + injected by vozka's engine). */
const REQUIRED_VARS = ['PROPUSTKA_HUMAN_EMAIL_DOMAINS', 'PROPUSTKA_OIDC_ISSUER', 'PROPUSTKA_OIDC_CLIENT_ID']

/**
 * propustka's Worker vars per env. Local inlines safe dev placeholders; off-local reads the injected
 * `pipeline.vars` from `process.env` (vozka's engine guarantees the REQUIRED ones are present, so no
 * re-validation here). The native-auth SECRETS (`PROPUSTKA_SIGNING_KEYS`, `PROPUSTKA_OIDC_CLIENT_SECRET`)
 * are `pipeline.secrets` (vault → wrangler secret put), never placed in `vars` (oblaka serializes vars
 * verbatim into wrangler.jsonc — plaintext).
 */
const buildVars = (env: string): Record<string, string> => {
	if (env === 'local') {
		return {
			HUMAN_EMAIL_DOMAINS: '[]',
			HUMAN_EMAILS: '[]',
			IAM_BOOTSTRAP_ADMINS: '[]',
			SESSION_COOKIE_DOMAIN: '',
			OIDC_ISSUER: 'https://accounts.google.com',
			OIDC_CLIENT_ID: '',
			OIDC_SCOPES: '',
			OIDC_REQUIRE_VERIFIED_EMAIL: 'true',
		}
	}
	return {
		HUMAN_EMAIL_DOMAINS: process.env['PROPUSTKA_HUMAN_EMAIL_DOMAINS'] ?? '[]',
		// Optional (default '[]'): present only if set in the registry + injected.
		HUMAN_EMAILS: process.env['PROPUSTKA_HUMAN_EMAILS'] ?? '[]',
		IAM_BOOTSTRAP_ADMINS: process.env['PROPUSTKA_BOOTSTRAP_ADMINS'] ?? '[]',
		SESSION_COOKIE_DOMAIN: process.env['PROPUSTKA_SESSION_COOKIE_DOMAIN'] ?? '',
		OIDC_ISSUER: process.env['PROPUSTKA_OIDC_ISSUER'] ?? '',
		OIDC_CLIENT_ID: process.env['PROPUSTKA_OIDC_CLIENT_ID'] ?? '',
		OIDC_SCOPES: process.env['PROPUSTKA_OIDC_SCOPES'] ?? '',
		OIDC_REQUIRE_VERIFIED_EMAIL: process.env['PROPUSTKA_OIDC_REQUIRE_VERIFIED_EMAIL'] ?? 'true',
	}
}

/**
 * propustka's full Cloudflare resource graph for one environment — consolidated out of `oblaka.ts`. Both
 * the vozka deploy path (`defineApp` below) and the local-dev `oblaka.ts` shim call this.
 */
export const buildPropustkaWorker = (ctx: ResourceContext): Worker => {
	const { env, domain } = ctx

	return new Worker({
		dir: '.',
		name: 'propustka-worker', // app workers reference this name via ServiceReference
		main: './src/index.ts',
		compatibility_flags: ['nodejs_compat_v2'],
		compatibility_date: '2025-10-01',
		// Bind the admin hostname (`ctx.domain`) as a Custom Domain (auto DNS + cert + route); it serves
		// the admin SPA + the native auth/admin HTTP surface. App workers reach the IAM Worker via the
		// service binding, so this domain is only the human-facing surface. No domain → *.workers.dev.
		routes: domain !== undefined && domain !== '' ? [{ pattern: domain, custom_domain: true }] : [],
		observability: { enabled: true },
		// Daily prune of auth_log (retention: weeks); see scheduled() in src/index.ts.
		triggers: { crons: ['0 3 * * *'] },
		assets: {
			directory: '../admin-ui/dist',
			binding: 'ASSETS',
			// SPA deep links fall through to index.html.
			not_found_handling: 'single-page-application',
			// fetch() runs before static assets so /admin/* + /auth/* route to the Worker and the native
			// admin gate / login flow apply before any asset is served.
			run_worker_first: true,
		},
		bindings: {
			DB: new D1Database({ name: 'propustka', migrationsDir: './migrations', locationHint: 'weur' }),
		},
		vars: {
			ENVIRONMENT: env,
			// propustka's own origin (iss + OIDC redirect base) is its admin hostname.
			...(domain !== undefined && domain !== '' ? { ISSUER: `https://${domain}` } : { ISSUER: 'http://localhost:18191' }),
			...buildVars(env),
		},
	})
}

/**
 * propustka has NO app-level authz vocabulary of its own — it IS the IAM system; its admin endpoints are
 * gated by the built-in `iam.admin` action + bootstrap admins, not an app schema. Empty schema mirrors the
 * live propustka schema exactly (first reconcile is a no-op).
 */
const schema: AppSchema = { scopes: [], actions: [], roles: {} }

export default defineApp({
	id: PROPUSTKA_APP_ID,
	resources: buildPropustkaWorker,
	schema,
	pipeline: {
		// propustka's Worker source lives alongside this config (packages/worker).
		workerDir: '.',
		// Build the admin SPA into ../admin-ui/dist (the ASSETS directory) before deploy.
		build: 'bun run --filter @propustka/admin-ui build',
		// The native-auth secrets: the token signing keys + the OIDC client secret. Held in vozka's vault.
		// PROPUSTKA_PROVISIONING_KEY is the seeded provisioning bearer the control plane (vozka) uses to
		// reconcile schemas (resolveCaller admits it as a synthetic admin); optional, empty = disabled.
		secrets: ['PROPUSTKA_SIGNING_KEYS', 'PROPUSTKA_OIDC_CLIENT_SECRET', 'PROPUSTKA_PROVISIONING_KEY'],
		// Non-secret, environment/account-specific config (per-app-env registry), injected into process.env
		// before materialization. HUMAN_EMAILS + BOOTSTRAP_ADMINS are optional (default '[]'), so not required.
		vars: REQUIRED_VARS,
	},
})
