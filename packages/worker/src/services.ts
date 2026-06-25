import { type CfAccess, CfAccessClient } from './cfaccess'
import { Db } from './db'
import type { Env } from './env'
import { IdentityClient } from './identity'
import { type AccessApps, JwtValidator } from './jwt'
import { GoogleOidc } from './oidc'

/**
 * Pre-wired services + parsed config for every request. Handlers take `Services`
 * (or pick what they need off it) instead of reaching into `env` directly —
 * keeps them decoupled from the CF binding shape and easier to test.
 *
 * Per-isolate state (the jose JWKS cache inside `JwtValidator` and the
 * group-membership cache inside `IdentityClient`) is memoised at module scope and
 * reused across requests in the same isolate — `buildServices` is cheap to call
 * per request.
 */
export interface Services {
	readonly db: Db
	readonly jwt: JwtValidator
	readonly identity: IdentityClient
	/** Cloudflare Access surface (service tokens + apps/reusable-policies). Tests inject a fake. */
	readonly cfAccess: CfAccess
	/** Google OIDC relying-party client (the propustka-native login upstream). Tests inject a fake. */
	readonly oidc: GoogleOidc
	readonly config: Config
}

export interface Config {
	/** `{ aud → appId }` — the JWT audience set and verified app-identity map. */
	readonly accessApps: AccessApps
	/** Access team domain (JWKS issuer). */
	readonly team: string
	/**
	 * Who may pass Cloudflare Access as a HUMAN — owned centrally by propustka, applied to EVERY
	 * app's human-gated paths (`reconcileAccess`). Apps declare only which paths are human-gated.
	 */
	readonly human: {
		readonly emailDomains: readonly string[]
		readonly emails: readonly string[]
	}
	/** Bootstrap-admin emails (normally empty). Resolution-time only. */
	readonly bootstrapAdmins: ReadonlySet<string>
	readonly cfApiToken: string
	readonly cfAccountId: string
	readonly environment: string
	// ── propustka-native auth ──
	/** propustka's own origin — the `iss` of minted tokens and the OIDC redirect base. */
	readonly issuer: string
	/** `Domain` for the SSO session cookie (e.g. `.example.com`); empty = host-only. */
	readonly sessionCookieDomain: string
}

// ── Per-isolate memoised state ────────────────────────────────────────────────
// One validator/identity-client per isolate. Keyed by the config string that
// shapes them, so a (hypothetical) env change rebuilds rather than serving stale.

let cachedJwt: { key: string; validator: JwtValidator } | undefined
let cachedIdentity: IdentityClient | undefined

function getJwtValidator(team: string, accessApps: AccessApps): JwtValidator {
	const key = `${team}::${Object.keys(accessApps).sort().join(',')}`
	if (!cachedJwt || cachedJwt.key !== key) {
		cachedJwt = { key, validator: new JwtValidator(team, accessApps) }
	}
	return cachedJwt.validator
}

function parseAccessApps(raw: string): AccessApps {
	try {
		const parsed: unknown = JSON.parse(raw)
		if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
			return {}
		}
		const out: AccessApps = {}
		for (const [aud, app] of Object.entries(parsed)) {
			if (typeof app === 'string') {
				out[aud] = app
			}
		}
		return out
	} catch {
		return {}
	}
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
	const accessApps = parseAccessApps(env.ACCESS_APPS)
	if (!cachedIdentity) {
		cachedIdentity = new IdentityClient()
	}
	return {
		db: new Db(env.DB),
		jwt: getJwtValidator(env.TEAM, accessApps),
		identity: cachedIdentity,
		cfAccess: new CfAccessClient(env.CF_API_TOKEN, env.CF_ACCOUNT_ID),
		oidc: new GoogleOidc({
			clientId: env.GOOGLE_CLIENT_ID,
			clientSecret: env.GOOGLE_CLIENT_SECRET,
			redirectUri: `${env.ISSUER}/auth/callback`,
		}),
		config: {
			accessApps,
			team: env.TEAM,
			human: {
				emailDomains: parseStringArray(env.HUMAN_EMAIL_DOMAINS),
				emails: parseStringArray(env.HUMAN_EMAILS),
			},
			bootstrapAdmins: parseBootstrapAdmins(env.IAM_BOOTSTRAP_ADMINS),
			cfApiToken: env.CF_API_TOKEN,
			cfAccountId: env.CF_ACCOUNT_ID,
			environment: env.ENVIRONMENT,
			issuer: env.ISSUER,
			sessionCookieDomain: env.SESSION_COOKIE_DOMAIN,
		},
	}
}
