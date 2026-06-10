import { D1Database, define, Worker } from 'oblaka-iac'

/**
 * Vars (and the two CF secrets, carried via vars on non-local) for each env.
 * Local inlines safe dev values; stage/prod read from `process.env` (CI sets them)
 * and throw loudly if missing — the opice `envVarsFor` pattern — so we never ship a
 * half-configured deploy. See architecture.md → Provisioning.
 */
interface PropustkaVars {
	ACCESS_APPS: string
	TEAM: string
	IAM_BOOTSTRAP_ADMINS: string
	CF_API_TOKEN: string
	CF_ACCOUNT_ID: string
}

function buildVars(env: string): PropustkaVars {
	if (env === 'local') {
		// Access doesn't exist locally; these are placeholders so the Worker boots.
		// Real JWT/get-identity integration is exercised against a real Access host.
		return {
			ACCESS_APPS: '{}',
			TEAM: 'https://example.cloudflareaccess.com',
			IAM_BOOTSTRAP_ADMINS: '[]',
			CF_API_TOKEN: 'local-cf-api-token',
			CF_ACCOUNT_ID: 'local-cf-account-id',
		}
	}

	const accessApps = process.env['PROPUSTKA_ACCESS_APPS']
	const team = process.env['PROPUSTKA_TEAM']
	const cfApiToken = process.env['CF_API_TOKEN']
	const cfAccountId = process.env['CF_ACCOUNT_ID']
	const missing = [
		['PROPUSTKA_ACCESS_APPS', accessApps],
		['PROPUSTKA_TEAM', team],
		['CF_API_TOKEN', cfApiToken],
		['CF_ACCOUNT_ID', cfAccountId],
	].filter(([, value]) => !value).map(([name]) => name)
	if (missing.length > 0) {
		throw new Error(
			`Missing ${missing.join(', ')} for env=${env}. Set them as environment variables before running oblaka.`,
		)
	}

	return {
		ACCESS_APPS: accessApps as string,
		TEAM: team as string,
		// Normally empty; the first admin is bootstrapped, then the var is emptied.
		IAM_BOOTSTRAP_ADMINS: process.env['PROPUSTKA_BOOTSTRAP_ADMINS'] ?? '[]',
		CF_API_TOKEN: cfApiToken as string,
		CF_ACCOUNT_ID: cfAccountId as string,
	}
}

const KNOWN_ENVS = new Set(['local', 'stage', 'prod'])

export default define(({ env }) => {
	if (!KNOWN_ENVS.has(env)) {
		throw new Error(`Unknown environment ${env}`)
	}
	const vars = buildVars(env)

	return new Worker({
		dir: '.',
		name: 'propustka-worker', // app workers reference this name via ServiceReference
		main: './src/index.ts',
		compatibility_flags: ['nodejs_compat_v2'],
		compatibility_date: '2025-10-01',
		observability: { enabled: true },
		// Daily prune of auth_log (retention: weeks); see scheduled() in src/index.ts.
		triggers: { crons: ['0 3 * * *'] },
		assets: {
			directory: '../admin-ui/dist',
			binding: 'ASSETS',
			// SPA deep links fall through to index.html.
			not_found_handling: 'single-page-application',
			// fetch() runs before static assets so /admin/* routes to the API and the
			// Access gate applies before any asset is served.
			run_worker_first: true,
		},
		bindings: {
			DB: new D1Database({
				name: 'propustka',
				migrationsDir: './migrations',
				locationHint: 'weur',
			}),
		},
		vars: {
			ENVIRONMENT: env,
			...vars,
		},
	})
})
