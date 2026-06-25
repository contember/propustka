// propustka's deploy surface for VOZKA — folds `oblaka.ts` + `propustka.access.ts` (+ its empty authz
// schema) into ONE `vozka-config` `defineApp`. vozka's engine loads this to deploy propustka itself:
// materialize the resource graph (provision via oblaka), reconcile its own Access front door into
// propustka, and run the pipeline. `oblaka.ts` stays as the local-dev shim (imports `buildPropustkaWorker`).
//
// propustka is config-heavy: its non-secret deploy vars (ACCESS_APPS / TEAM / HUMAN_* / CF_ACCOUNT_ID) are
// environment/account-specific and live in vozka's per-app-env registry, declared in `pipeline.vars` and
// injected into `process.env` before `resources()` runs (the SAME `process.env` reads the old `oblaka.ts`
// did). CF_ACCOUNT_ID is just an account identifier (non-sensitive), so it's a var. The one real secret is
// the CF Access API write token (CF_API_TOKEN), a `pipeline.secret` (vault → `wrangler secret put`). The
// Custom Domain route comes from `ctx.domain` (replacing PROPUSTKA_HOSTNAME).

import type { AppAccess, AppSchema, ResourceContext } from 'vozka-config'
import { D1Database, defineApp, Worker } from 'vozka-config'

// Stable app id — the value propustka-admin's Access app `aud` maps to in PROPUSTKA_ACCESS_APPS, AND the
// legacy `propustka-state` oblaka namespace prefix, so the first vozka deploy CONTINUES existing cf-state.
const PROPUSTKA_APP_ID = 'propustka'

/** The non-secret deploy vars propustka REQUIRES off-local (validated + injected by vozka's engine). */
const REQUIRED_VARS = ['PROPUSTKA_ACCESS_APPS', 'PROPUSTKA_TEAM', 'PROPUSTKA_HUMAN_EMAIL_DOMAINS']

/**
 * propustka's Worker vars per env. Local inlines safe dev placeholders (Access doesn't exist locally);
 * off-local reads the injected `pipeline.vars` from `process.env` (vozka's engine guarantees the REQUIRED
 * ones are present, so no re-validation here — a missing required var already failed the deploy). The CF
 * Access API write TOKEN is a SECRET (pipeline.secrets, vault → wrangler secret put), never placed in `vars`
 * (oblaka serializes vars verbatim into wrangler.jsonc — plaintext); CF_ACCOUNT_ID is non-sensitive so it IS
 * a var (set below in the off-local branch).
 */
const buildVars = (env: string): Record<string, string> => {
	if (env === 'local') {
		return {
			ACCESS_APPS: '{}',
			TEAM: 'https://example.cloudflareaccess.com',
			HUMAN_EMAIL_DOMAINS: '[]',
			HUMAN_EMAILS: '[]',
			IAM_BOOTSTRAP_ADMINS: '[]',
		}
	}
	return {
		ACCESS_APPS: process.env['PROPUSTKA_ACCESS_APPS'] ?? '{}',
		TEAM: process.env['PROPUSTKA_TEAM'] ?? '',
		HUMAN_EMAIL_DOMAINS: process.env['PROPUSTKA_HUMAN_EMAIL_DOMAINS'] ?? '[]',
		// CF account id — non-secret, so a var (read by the propustka worker's CfAccessClient at runtime).
		CF_ACCOUNT_ID: process.env['CF_ACCOUNT_ID'] ?? '',
		// Optional (default '[]'): present only if set in the registry + injected.
		HUMAN_EMAILS: process.env['PROPUSTKA_HUMAN_EMAILS'] ?? '[]',
		IAM_BOOTSTRAP_ADMINS: process.env['PROPUSTKA_BOOTSTRAP_ADMINS'] ?? '[]',
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
		// Bind the admin hostname (`ctx.domain`) as a Custom Domain (auto DNS + cert + route); Access fronts
		// it. App workers reach the IAM Worker via the service binding (no Access), so this domain is only
		// for the admin SPA + the HTTP admin API. No domain → *.workers.dev.
		routes: domain !== undefined && domain !== '' ? [{ pattern: domain, custom_domain: true }] : [],
		observability: { enabled: true },
		// Daily prune of auth_log (retention: weeks); see scheduled() in src/index.ts.
		triggers: { crons: ['0 3 * * *'] },
		assets: {
			directory: '../admin-ui/dist',
			binding: 'ASSETS',
			// SPA deep links fall through to index.html.
			not_found_handling: 'single-page-application',
			// fetch() runs before static assets so /admin/* routes to the API and the Access gate applies
			// before any asset is served.
			run_worker_first: true,
		},
		bindings: {
			DB: new D1Database({ name: 'propustka', migrationsDir: './migrations', locationHint: 'weur' }),
		},
		vars: {
			ENVIRONMENT: env,
			...buildVars(env),
		},
	})
}

/**
 * propustka-admin's OWN Cloudflare Access front door, reconciled into propustka (self-referential — the
 * one app that gates the admin endpoint every other app reconciles through). ONE gated admin host:
 * machines (app provisioning keys, service tokens) + humans. WHO the humans are is propustka's central
 * HUMAN_EMAIL_DOMAINS/HUMAN_EMAILS. Mirrors the live propustka access exactly (first reconcile is a no-op).
 *
 * `destinations` are USED only when CREATING a missing CF app; for the existing propustka-admin app the
 * reconcile preserves them. The placeholder fallback keeps this importable on the no-domain shim path.
 */
const buildAccess = (): AppAccess => {
	const host = process.env['PROPUSTKA_HOSTNAME'] ?? 'unset.propustka.invalid'
	return {
		apps: [
			{
				key: 'admin',
				name: 'propustka-admin',
				destinations: [host],
				sessionDuration: '24h',
				rules: [{ kind: 'service-auth' }, { kind: 'human' }],
			},
		],
	}
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
	access: buildAccess(),
	schema,
	pipeline: {
		// propustka's Worker source lives alongside this config (packages/worker).
		workerDir: '.',
		// Build the admin SPA into ../admin-ui/dist (the ASSETS directory) before deploy.
		build: 'bun run --filter @propustka/admin-ui build',
		// CF Access API write token for runtime service-token provisioning. The one real secret; held in vozka's vault.
		secrets: ['CF_API_TOKEN'],
		// Non-secret, environment/account-specific config (per-app-env registry), injected into process.env
		// before materialization. CF_ACCOUNT_ID rides here too (an account identifier, not a secret).
		// HUMAN_EMAILS + BOOTSTRAP_ADMINS are optional (default '[]') so not required here.
		vars: [...REQUIRED_VARS, 'CF_ACCOUNT_ID'],
	},
})
