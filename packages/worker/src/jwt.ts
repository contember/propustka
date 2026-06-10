import { createRemoteJWKSet, type JWTPayload, jwtVerify } from 'jose'

/**
 * JWT validation for Cloudflare Access tokens. All of this lives in one Worker so
 * the remote JWK set is cached per-isolate (jose handles caching) — a key reason
 * validation is centralised here rather than reimplemented per app.
 *
 * SECURITY NOTE (hard requirement 3): the app id used for the auth log and the
 * request context is the *verified* one derived from the token's `aud`, NEVER the
 * SDK-passed `app`. The SDK-passed value is trusted only where no token exists
 * (audit(), redeemCapability(), failure-path log rows) — for labeling, not as a
 * security boundary. Principal identity is likewise resolved from the verified
 * token, never app-asserted.
 */

/** The verified outcome of validating an Access JWT. */
export type JwtValidation =
	| {
		ok: true
		/** Verified app id resolved from `ACCESS_APPS[aud]`. */
		app: string
		/** 'user' (identity login: `email` + `sub`) vs 'service' (service token: `common_name`). */
		kind: 'user'
		email: string
		sub: string
	}
	| {
		ok: true
		app: string
		kind: 'service'
		/** The service token's Client ID — used as the principal `external_id`. */
		commonName: string
	}
	| {
		ok: false
		/** Caller-facing reason; apps must not branch on the nuance. */
		reason: 'missing_token' | 'invalid_token'
		/**
		 * Finer-grained reason for the auth log only. `aud_not_configured` flags a
		 * token that verified cryptographically but whose aud is not in ACCESS_APPS
		 * (an expected onboarding gap, not an attack).
		 */
		logReason: string
	}

/** ACCESS_APPS already parsed into a `{ aud → appId }` map. */
export type AccessApps = Record<string, string>

/**
 * Wraps a remote JWK set kept at isolate scope (jose caches the fetched keys on
 * it). One instance per Worker isolate; created lazily and reused across requests.
 */
export class JwtValidator {
	private readonly jwks: ReturnType<typeof createRemoteJWKSet>

	constructor(
		private readonly team: string,
		private readonly accessApps: AccessApps,
	) {
		this.jwks = createRemoteJWKSet(new URL(`${team}/cdn-cgi/access/certs`))
	}

	/**
	 * Validate a `Cf-Access-Jwt-Assertion` token. Never throws — returns a
	 * structured failure on any problem.
	 */
	async validate(token: string | null): Promise<JwtValidation> {
		if (!token) {
			return { ok: false, reason: 'missing_token', logReason: 'missing_token' }
		}

		let payload: JWTPayload
		try {
			// `aud` is a SET, not a single value: every onboarded Access application
			// has its own AUD tag and this Worker serves many apps. jose accepts a
			// string[] audience — pass all configured AUDs. `issuer` is the team domain.
			const result = await jwtVerify(token, this.jwks, {
				issuer: this.team,
				audience: Object.keys(this.accessApps),
			})
			payload = result.payload
		} catch {
			// Bad signature, expired, wrong issuer, or aud not in the configured set:
			// all genuinely invalid from the caller's perspective.
			return { ok: false, reason: 'invalid_token', logReason: 'invalid_token' }
		}

		// Resolve the verified app id from the matched aud. jose has already proven
		// the token carries one of our configured AUDs, but `aud` may be an array;
		// find the one that maps to a configured app.
		const app = this.resolveApp(payload.aud)
		if (app === undefined) {
			// Verified token whose aud is not a key of ACCESS_APPS. With `audience`
			// passed to jwtVerify this is normally already rejected above; this is a
			// defensive branch (e.g. aud is an array carrying an extra unknown tag).
			// Expected misconfiguration — a newly onboarded app nobody added to the
			// env. Caller sees invalid_token; the log records the real reason.
			return { ok: false, reason: 'invalid_token', logReason: 'aud_not_configured' }
		}

		// Identity login carries `email` + `sub`; a service token carries
		// `common_name` (= the token Client ID). Distinguish by which is present.
		const email = typeof payload['email'] === 'string' ? payload['email'] : undefined
		const commonName = typeof payload['common_name'] === 'string' ? payload['common_name'] : undefined

		if (email && typeof payload.sub === 'string' && payload.sub.length > 0) {
			return { ok: true, app, kind: 'user', email, sub: payload.sub }
		}
		if (commonName) {
			return { ok: true, app, kind: 'service', commonName }
		}

		// Verified token but neither identity shape — malformed for our purposes.
		return { ok: false, reason: 'invalid_token', logReason: 'no_identity_claim' }
	}

	private resolveApp(aud: string | string[] | undefined): string | undefined {
		if (typeof aud === 'string') {
			return this.accessApps[aud]
		}
		if (Array.isArray(aud)) {
			for (const tag of aud) {
				const app = this.accessApps[tag]
				if (app !== undefined) {
					return app
				}
			}
		}
		return undefined
	}
}
