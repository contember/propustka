import { D1Database, define, Worker } from 'oblaka-iac'

/**
 * Non-secret vars for each env. Local inlines safe dev values; stage/prod read from
 * `process.env` (CI sets them) and throw loudly if missing — the opice `envVarsFor`
 * pattern — so we never ship a half-configured deploy. See architecture.md → Provisioning.
 *
 * The propustka-native auth SECRETS (`PROPUSTKA_SIGNING_KEYS`, `PROPUSTKA_OIDC_CLIENT_SECRET`) are
 * deliberately NOT part of this object: they must never be written into the generated
 * `wrangler.jsonc` `vars` (plaintext, visible in the dashboard). oblaka serializes the whole Worker
 * config verbatim, so anything in `vars` ships unencrypted. Following the oblaka idiom (see
 * project-portfolio-manager's `oblaka.ts`), secret values are provisioned out-of-band:
 *   - remote (stage/prod): `wrangler secret put PROPUSTKA_SIGNING_KEYS` / `PROPUSTKA_OIDC_CLIENT_SECRET`
 *   - local: a `packages/worker/.dev.vars` file, which lopata loads on top of `vars`.
 * We still validate their presence in `process.env` on stage/prod so a misconfigured deploy fails
 * loudly, but we never place the values into the Worker config.
 */
interface PropustkaVars {
	// Central human-admission allowlist (JSON arrays; a `*` entry = admit-all) — who may log in.
	HUMAN_EMAIL_DOMAINS: string
	HUMAN_EMAILS: string
	IAM_BOOTSTRAP_ADMINS: string
	// propustka-native auth (propustka issues its own tokens). The signing keys + OIDC client SECRET
	// are NOT here — they ship out-of-band (`.dev.vars` local / `wrangler secret` remote).
	ISSUER: string
	SESSION_COOKIE_DOMAIN: string
	OIDC_ISSUER: string
	OIDC_CLIENT_ID: string
	OIDC_SCOPES: string
	OIDC_REQUIRE_VERIFIED_EMAIL: string
}

function buildVars(env: string, hostname: string | undefined): PropustkaVars {
	if (env === 'local') {
		// No real OIDC upstream locally; these are placeholders so the Worker boots. The signing key
		// is ephemeral (empty PROPUSTKA_SIGNING_KEYS), so login flows are exercised against a real IdP
		// host, not here. OIDC_ISSUER is a placeholder (discovery never runs in dev).
		return {
			HUMAN_EMAIL_DOMAINS: '[]',
			HUMAN_EMAILS: '[]',
			IAM_BOOTSTRAP_ADMINS: '[]',
			// `dev` serves on :18191 (see package.json).
			ISSUER: 'http://localhost:18191',
			SESSION_COOKIE_DOMAIN: '',
			OIDC_ISSUER: 'https://accounts.google.com',
			OIDC_CLIENT_ID: '',
			OIDC_SCOPES: '',
			OIDC_REQUIRE_VERIFIED_EMAIL: 'true',
		}
	}

	// Central human-admission allowlist: domains are required (the primary case), emails optional.
	const humanEmailDomains = process.env['PROPUSTKA_HUMAN_EMAIL_DOMAINS']
	// propustka-native auth: OIDC issuer + client id (public), and the signing-keys / client-secret
	// SECRETS validated-present here but provisioned out-of-band (never written into vars).
	const oidcIssuer = process.env['PROPUSTKA_OIDC_ISSUER']
	const oidcClientId = process.env['PROPUSTKA_OIDC_CLIENT_ID']
	const signingKeys = process.env['PROPUSTKA_SIGNING_KEYS']
	const oidcClientSecret = process.env['PROPUSTKA_OIDC_CLIENT_SECRET']
	const missing = [
		['PROPUSTKA_HUMAN_EMAIL_DOMAINS', humanEmailDomains],
		['PROPUSTKA_HOSTNAME', hostname],
		['PROPUSTKA_OIDC_ISSUER', oidcIssuer],
		['PROPUSTKA_OIDC_CLIENT_ID', oidcClientId],
		['PROPUSTKA_SIGNING_KEYS', signingKeys],
		['PROPUSTKA_OIDC_CLIENT_SECRET', oidcClientSecret],
	].filter(([, value]) => !value).map(([name]) => name)
	if (missing.length > 0) {
		throw new Error(
			`Missing ${missing.join(', ')} for env=${env}. Set them as environment variables before running oblaka.`,
		)
	}

	return {
		HUMAN_EMAIL_DOMAINS: humanEmailDomains as string,
		HUMAN_EMAILS: process.env['PROPUSTKA_HUMAN_EMAILS'] ?? '[]',
		// Normally empty; the first admin is bootstrapped, then the var is emptied.
		IAM_BOOTSTRAP_ADMINS: process.env['PROPUSTKA_BOOTSTRAP_ADMINS'] ?? '[]',
		// propustka's own origin (iss + OIDC redirect base) is its admin hostname.
		ISSUER: `https://${hostname as string}`,
		SESSION_COOKIE_DOMAIN: process.env['PROPUSTKA_SESSION_COOKIE_DOMAIN'] ?? '',
		OIDC_ISSUER: oidcIssuer as string,
		OIDC_CLIENT_ID: oidcClientId as string,
		OIDC_SCOPES: process.env['PROPUSTKA_OIDC_SCOPES'] ?? '',
		OIDC_REQUIRE_VERIFIED_EMAIL: process.env['PROPUSTKA_OIDC_REQUIRE_VERIFIED_EMAIL'] ?? 'true',
	}
}

const KNOWN_ENVS = new Set(['local', 'stage', 'prod', 'mangoweb'])

export default define(({ env }) => {
	if (!KNOWN_ENVS.has(env)) {
		throw new Error(`Unknown environment ${env}`)
	}

	// Admin hostname, bound below as a Custom Domain. Driven per-env by the PROPUSTKA_HOSTNAME
	// deploy var (a GitHub Environment variable the workflow passes) so each target gets its OWN
	// domain — contember prod -> propustka.contember.com, manGoweb -> propustka.mgwsite.com —
	// instead of the hostname being hardcoded to one account. Unset (stage/local) -> *.workers.dev.
	// It is ALSO propustka's own `iss`/OIDC origin (see buildVars → ISSUER), so it's required remotely.
	const hostname = env === 'local' ? undefined : process.env['PROPUSTKA_HOSTNAME']

	const vars = buildVars(env, hostname)

	return new Worker({
		dir: '.',
		name: 'propustka-worker', // app workers reference this name via ServiceReference
		main: './src/index.ts',
		compatibility_flags: ['nodejs_compat_v2'],
		compatibility_date: '2025-10-01',
		// Bind the admin hostname (PROPUSTKA_HOSTNAME, above) as a Custom Domain (auto-creates DNS +
		// cert + route); it serves the admin SPA + the native auth/admin HTTP surface. Declared HERE as
		// IaC because oblaka regenerates wrangler.jsonc on every deploy — a domain attached only in the
		// dashboard gets wiped by the next `wrangler deploy`. App workers reach the IAM Worker via the
		// service binding, so this domain is only the human-facing surface. Unset (stage/local) -> *.workers.dev.
		routes: hostname ? [{ pattern: hostname, custom_domain: true }] : [],
		observability: { enabled: true },
		// Daily prune of auth_log (retention: weeks); see scheduled() in src/index.ts.
		triggers: { crons: ['0 3 * * *'] },
		assets: {
			directory: '../admin-ui/dist',
			binding: 'ASSETS',
			// SPA deep links fall through to index.html.
			not_found_handling: 'single-page-application',
			// fetch() runs before static assets so /admin/* + /auth/* route to the Worker and the
			// native admin gate / login flow apply before any asset is served.
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
