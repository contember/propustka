import { Db } from './db'
import type { Env } from './env'
import { OidcClient } from './oidc'

/**
 * Pre-wired services + parsed config for every request. Handlers take `Services`
 * (or pick what they need off it) instead of reaching into `env` directly —
 * keeps them decoupled from the CF binding shape and easier to test.
 */
export interface Services {
	readonly db: Db
	/** OIDC relying-party client (the propustka-native login upstream). Tests inject a fake. */
	readonly oidc: OidcClient
	readonly config: Config
}

export interface Config {
	/**
	 * The central human-admission allowlist — who may self-provision as a HUMAN at login. A `*` entry
	 * in either list means admit-all; otherwise an exact email or matching domain. Owned by propustka
	 * (deploy vars `PROPUSTKA_HUMAN_EMAIL_DOMAINS` / `PROPUSTKA_HUMAN_EMAILS`).
	 */
	readonly human: {
		readonly emailDomains: readonly string[]
		readonly emails: readonly string[]
	}
	/** Bootstrap-admin emails (normally empty). Always admitted; resolve to the global `admin` role. */
	readonly bootstrapAdmins: ReadonlySet<string>
	readonly environment: string
	// ── propustka-native auth ──
	/** propustka's own origin — the `iss` of minted tokens and the OIDC redirect base. */
	readonly issuer: string
	/** `Domain` for the SSO session cookie (e.g. `.example.com`); empty = host-only. */
	readonly sessionCookieDomain: string
}

/** Parse a JSON array of strings (the central human-domain/email lists); [] on anything malformed. */
function parseStringArray(raw: string): string[] {
	try {
		const parsed: unknown = JSON.parse(raw)
		return Array.isArray(parsed) ? parsed.filter((v): v is string => typeof v === 'string') : []
	} catch {
		return []
	}
}

function parseBootstrapAdmins(raw: string): Set<string> {
	try {
		const parsed: unknown = JSON.parse(raw)
		if (!Array.isArray(parsed)) {
			return new Set()
		}
		return new Set(parsed.filter((v): v is string => typeof v === 'string'))
	} catch {
		return new Set()
	}
}

export function buildServices(env: Env): Services {
	return {
		db: new Db(env.DB),
		oidc: new OidcClient({
			issuer: env.OIDC_ISSUER,
			clientId: env.OIDC_CLIENT_ID,
			clientSecret: env.OIDC_CLIENT_SECRET,
			redirectUri: `${env.ISSUER}/auth/callback`,
			scopes: env.OIDC_SCOPES,
			// Require a verified email by default; opt out only with the explicit string 'false'.
			requireVerifiedEmail: env.OIDC_REQUIRE_VERIFIED_EMAIL !== 'false',
		}),
		config: {
			human: {
				emailDomains: parseStringArray(env.HUMAN_EMAIL_DOMAINS),
				emails: parseStringArray(env.HUMAN_EMAILS),
			},
			bootstrapAdmins: parseBootstrapAdmins(env.IAM_BOOTSTRAP_ADMINS),
			environment: env.ENVIRONMENT,
			issuer: env.ISSUER,
			sessionCookieDomain: env.SESSION_COOKIE_DOMAIN,
		},
	}
}
