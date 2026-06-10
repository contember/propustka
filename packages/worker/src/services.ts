import type { PermissionEntry } from '@propustka/core'
import { RESOLUTION_TTL_MS, TtlCache } from './cache'
import { Db } from './db'
import type { Env } from './env'
import { IdentityClient } from './identity'
import { type AccessApps, JwtValidator } from './jwt'

/**
 * Pre-wired services + parsed config for every request. Handlers take `Services`
 * (or pick what they need off it) instead of reaching into `env` directly —
 * keeps them decoupled from the CF binding shape and easier to test.
 *
 * Per-isolate state (the jose JWKS cache inside `JwtValidator`, the get-identity
 * cache inside `IdentityClient`, and the resolved-principal cache) is memoised at
 * module scope and reused across requests in the same isolate — `buildServices`
 * is cheap to call per request.
 */
export interface Services {
	readonly db: Db
	readonly jwt: JwtValidator
	readonly identity: IdentityClient
	/** Per-isolate cache of resolved principal permissions; safe to be empty (falls to D1). */
	readonly resolutionCache: TtlCache<{ permissions: PermissionEntry[]; groupsUnavailable: boolean }>
	readonly config: Config
}

export interface Config {
	/** `{ aud → appId }` — the JWT audience set and verified app-identity map. */
	readonly accessApps: AccessApps
	/** Access team domain (JWKS issuer). */
	readonly team: string
	/** Bootstrap-admin emails (normally empty). Resolution-time only. */
	readonly bootstrapAdmins: ReadonlySet<string>
	readonly cfApiToken: string
	readonly cfAccountId: string
	readonly environment: string
}

// ── Per-isolate memoised state ────────────────────────────────────────────────
// One validator/identity-client/cache per isolate. Keyed by the config string that
// shapes them, so a (hypothetical) env change rebuilds rather than serving stale.

let cachedJwt: { key: string; validator: JwtValidator } | undefined
let cachedIdentity: IdentityClient | undefined
let cachedResolution: TtlCache<{ permissions: PermissionEntry[]; groupsUnavailable: boolean }> | undefined

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
	if (!cachedResolution) {
		cachedResolution = new TtlCache(RESOLUTION_TTL_MS)
	}
	return {
		db: new Db(env.DB),
		jwt: getJwtValidator(env.TEAM, accessApps),
		identity: cachedIdentity,
		resolutionCache: cachedResolution,
		config: {
			accessApps,
			team: env.TEAM,
			bootstrapAdmins: parseBootstrapAdmins(env.IAM_BOOTSTRAP_ADMINS),
			cfApiToken: env.CF_API_TOKEN,
			cfAccountId: env.CF_ACCOUNT_ID,
			environment: env.ENVIRONMENT,
		},
	}
}
