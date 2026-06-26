/**
 * propustka-native session authentication — the SDK side of "propustka issues its own tokens".
 *
 * Instead of the IAM Worker resolving a Cloudflare Access JWT on EVERY request (`IamClient.
 * authenticate`), the app's middleware here verifies a short-lived per-app permission token LOCALLY
 * against propustka's published JWKS — no per-request round-trip. The token lives in the `px_token`
 * cookie; the browser's long-lived `px_session` SSO cookie is exchanged for a fresh one (`mintToken`
 * over the binding) only when the permission token is missing or near expiry (≈ once per TTL).
 *
 * Flow per request:
 *   1. valid, not-near-expiry `px_token` → verify locally, done (no binding call).
 *   2. else → `mintToken({ session })` over the binding → set a fresh `px_token`, proceed.
 *   3. no/!invalid session → unauthenticated; the caller redirects the browser to `loginUrl`.
 *
 * The JWKS is fetched once per isolate over the binding (which never traverses the Access edge) and
 * cached per binding; a key rotation (unknown kid) triggers one refetch.
 */

import {
	accessClaimsToResolved,
	type AccessTokenClaims,
	type IamRpc,
	type Jwks,
	parseAccessClaims,
	SESSION_COOKIE,
	TOKEN_COOKIE,
	TOKEN_REFRESH_SKEW_SECONDS,
} from '@propustka/core'
import { createLocalJWKSet, errors as joseErrors, jwtVerify } from 'jose'
import { buildAuthContext } from './client'
import type { AuthContext } from './types'

export interface SessionAuthConfig {
	/** propustka's origin — verifies the token `iss` and is the base for the `/auth/login` redirect. */
	issuer: string
	/** Force the `px_token` cookie's `Secure` flag; default = derived from the request URL scheme. */
	secure?: boolean
}

/**
 * The outcome of session authentication. On success, `setCookie` (when present) is the freshly
 * minted `px_token` the caller MUST attach to its response. On failure, `loginUrl` is where to
 * 302 the browser to log in. `reason` mirrors `mintToken`'s.
 */
export type SessionAuthResult =
	| { ok: true; context: AuthContext; setCookie?: string }
	| { ok: false; reason: 'no_session' | 'invalid_session' | 'unknown_principal' | 'disabled'; loginUrl: string }

/** How long a fetched JWKS is reused before a refetch (a rotation also forces one on demand). */
const JWKS_TTL_SECONDS = 600

export class PropustkaAuth {
	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
		private readonly config: SessionAuthConfig,
	) {}

	/**
	 * Authenticate a request. Verifies the cached permission token locally when possible; otherwise
	 * mints a fresh one from the SSO session. Never throws — a failure is a typed `ok:false` result.
	 */
	async authenticate(request: Request): Promise<SessionAuthResult> {
		const now = Math.floor(Date.now() / 1000)
		const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID()
		const cookieHeader = request.headers.get('Cookie')

		// 1. Fast path — a valid, not-near-expiry token authorizes with NO binding call.
		const tokenCookie = readCookie(cookieHeader, TOKEN_COOKIE)
		if (tokenCookie) {
			const claims = await this.verify(tokenCookie)
			if (claims && claims.exp - now > TOKEN_REFRESH_SKEW_SECONDS) {
				const context = this.context(claims, requestId)
				if (context) {
					return { ok: true, context }
				}
			}
		}

		// 2. Refresh path — exchange the SSO session for a fresh per-app token (≈ once per TTL).
		const session = readCookie(cookieHeader, SESSION_COOKIE)
		const minted = await this.binding.mintToken({ app: this.appId, session, requestId })
		if (!minted.ok) {
			return { ok: false, reason: minted.reason, loginUrl: this.loginUrl(request) }
		}
		const claims = await this.verify(minted.token)
		const context = claims && this.context(claims, requestId)
		if (!context) {
			// We just minted it — a verification miss means a config/clock problem; force re-login.
			return { ok: false, reason: 'invalid_session', loginUrl: this.loginUrl(request) }
		}
		return {
			ok: true,
			context,
			setCookie: tokenCookieHeader(minted.token, minted.expiresAt - now, this.secure(request)),
		}
	}

	/** Where to send the browser to log in, returning to the current URL afterwards. */
	loginUrl(request: Request): string {
		return `${trimSlash(this.config.issuer)}/auth/login?redirect=${encodeURIComponent(request.url)}`
	}

	/** Build an AuthContext from verified claims; null for an anonymous token (no principal). */
	private context(claims: AccessTokenClaims, requestId: string): AuthContext | null {
		const resolved = accessClaimsToResolved(claims, requestId)
		return resolved ? buildAuthContext(this.binding, this.appId, resolved) : null
	}

	/** Verify a token against the published JWKS and narrow it to access claims; null on any miss. */
	private async verify(token: string): Promise<AccessTokenClaims | null> {
		let payload = await this.verifyWith(token, false)
		if (payload === NO_KEY) {
			// Unknown kid — a key was rotated in. Refetch the JWKS once and retry.
			payload = await this.verifyWith(token, true)
		}
		if (payload === NO_KEY || payload === null) {
			return null
		}
		return parseAccessClaims(payload)
	}

	/** Returns the payload, `null` on a genuine verification failure, or `NO_KEY` on a kid miss. */
	private async verifyWith(token: string, force: boolean): Promise<unknown> {
		const jwks = await this.jwks(force)
		try {
			const { payload } = await jwtVerify(token, jwks, { issuer: this.config.issuer, audience: this.appId })
			return payload
		} catch (err) {
			return err instanceof joseErrors.JWKSNoMatchingKey ? NO_KEY : null
		}
	}

	private async jwks(force: boolean): Promise<ReturnType<typeof createLocalJWKSet>> {
		const now = Math.floor(Date.now() / 1000)
		const cached = jwksCache.get(this.binding)
		if (!force && cached && cached.expiresAt > now) {
			return cached.verifier
		}
		const keys: Jwks = await this.binding.getJwks()
		const verifier = createLocalJWKSet(keys)
		jwksCache.set(this.binding, { verifier, expiresAt: now + JWKS_TTL_SECONDS })
		return verifier
	}

	private secure(request: Request): boolean {
		return this.config.secure ?? new URL(request.url).protocol === 'https:'
	}
}

/** Sentinel distinguishing "no signing key matched (kid rotation)" from a real verification failure. */
const NO_KEY = Symbol('no-matching-key')

/** JWKS verifier cached per binding (so it persists across the per-request SDK instances). */
const jwksCache = new WeakMap<object, { verifier: ReturnType<typeof createLocalJWKSet>; expiresAt: number }>()

/** Build the host-only `px_token` cookie carrying a freshly minted permission token. */
function tokenCookieHeader(token: string, maxAge: number, secure: boolean): string {
	const parts = [`${TOKEN_COOKIE}=${token}`, 'Path=/', `Max-Age=${Math.max(0, maxAge)}`, 'HttpOnly', 'SameSite=Lax']
	if (secure) {
		parts.push('Secure')
	}
	return parts.join('; ')
}

function readCookie(header: string | null, name: string): string | null {
	if (!header) {
		return null
	}
	for (const part of header.split(';')) {
		const eq = part.indexOf('=')
		if (eq !== -1 && part.slice(0, eq).trim() === name) {
			return part.slice(eq + 1).trim()
		}
	}
	return null
}

function trimSlash(url: string): string {
	return url.replace(/\/+$/, '')
}
