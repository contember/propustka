/**
 * propustka-native session authentication — the SDK side of "propustka issues its own tokens".
 *
 * Instead of the IAM Worker resolving a Cloudflare Access JWT on every request, the app's middleware
 * here (a) decides, per request path, WHICH credential kind is required (the in-process per-path gate
 * schema — `AppGates` — that replaced the deleted CF Access edge), then (b) resolves that credential,
 * verifying a short-lived per-app permission token LOCALLY against propustka's published JWKS (no
 * per-request round-trip). The token lives in the `px_token` cookie; the browser's long-lived
 * `px_session` SSO cookie is exchanged for a fresh one (`mintToken` over the binding) only when the
 * permission token is missing or near expiry (≈ once per TTL).
 *
 * Gate matching (precedence = `gates.rules` order; first matching+satisfiable rule wins):
 *   - `public`  → an anonymous AuthContext (`principal: null`), no binding call. Terminal.
 *   - `service` → a `px_` key (exchanged once via `mintFromKey`, cached) or a passthrough JWT
 *     (verified locally). ABSENT → fall through to the next matching rule; PRESENT-invalid → 401.
 *   - `human`   → a `px_session`/`px_token`. Missing/expired → fall through, remembering a `loginUrl`
 *     so the caller can 302 the browser to `/auth/login`.
 * A request matching NO rule is denied (fail-closed) — there is no edge in front anymore.
 *
 * The JWKS is fetched once per isolate over the binding (which never traverses any edge) and cached
 * per binding; a key rotation (unknown kid) triggers one refetch.
 */

import {
	type AccessTokenClaims,
	API_KEY_PREFIX,
	type AppGates,
	type CredentialLocation,
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
	/** The ordered per-path gate rules enforced in-process (replaced the CF Access edge). */
	gates: AppGates
}

/**
 * The outcome of authentication. On success, `setCookie` (when present) is the freshly minted
 * `px_token` the caller MUST attach to its response. On failure, `status` is the HTTP status to
 * return, and `loginUrl` (human-gated misses only) is where to 302 the browser to log in.
 */
export type SessionAuthResult =
	| { ok: true; context: AuthContext; setCookie?: string }
	| {
		ok: false
		reason: 'no_rule' | 'no_credential' | 'invalid_key' | 'no_session' | 'invalid_session' | 'unknown_principal' | 'disabled'
		status: 401 | 403
		/** Present ONLY for a human-gated miss — where the caller may 302 the browser to log in. */
		loginUrl?: string
	}

/** Why a `human` (session) attempt failed — mirrors `mintToken`'s reasons. */
type SessionFailureReason = 'no_session' | 'invalid_session' | 'unknown_principal' | 'disabled'

/** The cookie/session attempt's internal outcome, before the matcher maps it to a `SessionAuthResult`. */
type SessionAttempt =
	| { ok: true; context: AuthContext; setCookie?: string }
	| { ok: false; reason: SessionFailureReason }

/** How long a fetched JWKS is reused before a refetch (a rotation also forces one on demand). */
const JWKS_TTL_SECONDS = 600

export class PropustkaAuth {
	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
		private readonly config: SessionAuthConfig,
	) {}

	/**
	 * Authenticate a request against the per-path gates. Verifies the cached permission token locally
	 * when possible; otherwise mints a fresh one. Never throws — a failure is a typed `ok:false` result.
	 */
	async authenticate(request: Request): Promise<SessionAuthResult> {
		const now = Math.floor(Date.now() / 1000)
		const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID()
		const url = new URL(request.url)

		const applicable = this.config.gates.rules.filter((rule) => pathMatches(rule.path, url.pathname))
		if (applicable.length === 0) {
			// Fail closed — there is no edge in front, so an unmatched path is denied.
			return { ok: false, reason: 'no_rule', status: 403 }
		}

		// Remembers a human rule's miss (with its precise reason) so the caller can be 302'd to login
		// after exhausting all matching rules without satisfying one.
		let humanMiss: { reason: SessionFailureReason; loginUrl: string } | null = null

		for (const rule of applicable) {
			if (rule.kind === 'public') {
				return { ok: true, context: this.anonymousContext(requestId, now) }
			}
			if (rule.kind === 'service') {
				const raw = this.extractServiceCredential(request, url, rule.credential)
				if (raw === null) {
					continue // absent → fall through to the next matching rule
				}
				return this.authenticateBearer(raw, requestId, now) // present → terminal (ok | 401/403)
			}
			// human
			const attempt = await this.authenticateSession(request, requestId, now)
			if (attempt.ok) {
				return attempt
			}
			humanMiss = { reason: attempt.reason, loginUrl: this.loginUrl(request) }
		}

		if (humanMiss !== null) {
			return { ok: false, reason: humanMiss.reason, status: 401, loginUrl: humanMiss.loginUrl }
		}
		// Every matching rule was a `service` rule with no credential present.
		return { ok: false, reason: 'no_credential', status: 401 }
	}

	/**
	 * Redeem an opaque `px_` credential (or a passthrough JWT) into an `AuthContext` OFF the gate path —
	 * the seam a capability/share token uses (the token rides a query param or cookie, not a gated path).
	 * Reuses the exact `service`-bearer logic: a `px_` key is exchanged via `mintFromKey` (cached) and
	 * verified locally; a passthrough JWT is verified locally with no binding call. Never throws — a
	 * failure is a typed `ok:false` result the caller maps (a capability surface maps it to 404).
	 */
	redeemKey(token: string): Promise<SessionAuthResult> {
		const now = Math.floor(Date.now() / 1000)
		return this.authenticateBearer(token, crypto.randomUUID(), now)
	}

	/** The raw `service`-rule credential: the declared location, else `Authorization: Bearer`. Null if absent. */
	private extractServiceCredential(request: Request, url: URL, location: CredentialLocation | undefined): string | null {
		if (location !== undefined) {
			const raw = extractCredential(request, url, location)
			return raw === null || raw === '' ? null : raw
		}
		return readBearer(request.headers.get('Authorization'))
	}

	/**
	 * Authenticate a `service`-rule bearer. A `px_` opaque key is exchanged via `mintFromKey` (cached
	 * per isolate so the hot path is a local verify, no RPC); anything else is treated as an
	 * already-signed passthrough access token and verified locally. No Set-Cookie — the machine carries
	 * the credential itself. A present-but-invalid credential fails closed (no fall-through).
	 */
	private async authenticateBearer(bearer: string, requestId: string, now: number): Promise<SessionAuthResult> {
		if (bearer.startsWith(API_KEY_PREFIX)) {
			const cache = keyCacheFor(this.binding)
			const cached = cache.get(bearer)
			if (cached && cached.expiresAt - now > TOKEN_REFRESH_SKEW_SECONDS) {
				const claims = await this.verify(cached.token)
				if (claims) {
					return { ok: true, context: this.context(claims, requestId) }
				}
			}
			const minted = await this.binding.mintFromKey({ app: this.appId, key: bearer, requestId })
			if (!minted.ok) {
				return { ok: false, reason: minted.reason, status: minted.reason === 'invalid_key' ? 401 : 403 }
			}
			const claims = await this.verify(minted.token)
			if (!claims) {
				return { ok: false, reason: 'invalid_key', status: 401 }
			}
			cache.set(bearer, { token: minted.token, expiresAt: minted.expiresAt })
			return { ok: true, context: this.context(claims, requestId) }
		}

		// A passthrough JWT — verify locally, no binding call.
		const claims = await this.verify(bearer)
		if (!claims) {
			return { ok: false, reason: 'invalid_key', status: 401 }
		}
		return { ok: true, context: this.context(claims, requestId) }
	}

	/**
	 * Resolve a human via the `px_token` fast path, falling back to a `mintToken` exchange of the
	 * `px_session` SSO cookie. Returns an internal attempt the matcher maps to a `SessionAuthResult`
	 * (so it can attach a `loginUrl` only when the whole gate set is exhausted).
	 */
	private async authenticateSession(request: Request, requestId: string, now: number): Promise<SessionAttempt> {
		const cookieHeader = request.headers.get('Cookie')

		// Fast path — a valid, not-near-expiry token authorizes with NO binding call.
		const tokenCookie = readCookie(cookieHeader, TOKEN_COOKIE)
		if (tokenCookie) {
			const claims = await this.verify(tokenCookie)
			if (claims && claims.exp - now > TOKEN_REFRESH_SKEW_SECONDS) {
				return { ok: true, context: this.context(claims, requestId) }
			}
		}

		// Refresh path — exchange the SSO session for a fresh per-app token (≈ once per TTL).
		const session = readCookie(cookieHeader, SESSION_COOKIE)
		const minted = await this.binding.mintToken({ app: this.appId, session, requestId })
		if (!minted.ok) {
			return { ok: false, reason: minted.reason }
		}
		const claims = await this.verify(minted.token)
		if (!claims) {
			// We just minted it — a verification miss means a config/clock problem; force re-login.
			return { ok: false, reason: 'invalid_session' }
		}
		return {
			ok: true,
			context: this.context(claims, requestId),
			setCookie: tokenCookieHeader(minted.token, minted.expiresAt - now, this.secure(request)),
		}
	}

	/** An anonymous AuthContext (a `public` path) — no principal, empty perms, no binding call. */
	private anonymousContext(requestId: string, now: number): AuthContext {
		const claims: AccessTokenClaims = { iss: this.config.issuer, aud: this.appId, sub: 'anonymous', iat: now, exp: now, perms: [], label: null }
		return buildAuthContext(this.binding, this.appId, claims, requestId)
	}

	/** Where to send the browser to log in, returning to the current URL afterwards. */
	loginUrl(request: Request): string {
		return `${trimSlash(this.config.issuer)}/auth/login?redirect=${encodeURIComponent(request.url)}`
	}

	/** Build an AuthContext from verified claims (principal-bound or anonymous). */
	private context(claims: AccessTokenClaims, requestId: string): AuthContext {
		return buildAuthContext(this.binding, this.appId, claims, requestId)
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

/**
 * Per-binding cache of the access token minted from a `px_` credential, keyed by the credential. Lets
 * a machine that presents the same key on every request authorize by local verify (≈ one `mintFromKey`
 * per TTL) — the isolate-memory analogue of the browser's `px_token` cookie.
 */
const keyTokenCache = new WeakMap<object, Map<string, { token: string; expiresAt: number }>>()

function keyCacheFor(binding: object): Map<string, { token: string; expiresAt: number }> {
	let cache = keyTokenCache.get(binding)
	if (!cache) {
		cache = new Map()
		keyTokenCache.set(binding, cache)
	}
	return cache
}

/** Read the token out of an `Authorization: Bearer <token>` header. Null when absent/non-bearer. */
function readBearer(header: string | null): string | null {
	if (header === null) {
		return null
	}
	const match = /^Bearer\s+(.+)$/i.exec(header.trim())
	return match ? (match[1]?.trim() ?? null) : null
}

/** Pull the raw credential from a declared location. A header value may be bare or `Bearer <token>`. */
function extractCredential(request: Request, url: URL, source: CredentialLocation): string | null {
	if (source.in === 'header') {
		const value = request.headers.get(source.name)
		return value === null ? null : (readBearer(value) ?? value.trim())
	}
	if (source.in === 'query') {
		return url.searchParams.get(source.name)
	}
	return readCookie(request.headers.get('Cookie'), source.name)
}

/** Glob match where `*` matches any run of characters; the rest is literal. Anchored. */
function pathMatches(pattern: string, pathname: string): boolean {
	const regex = new RegExp(`^${pattern.split('*').map(escapeRegExp).join('.*')}$`)
	return regex.test(pathname)
}

function escapeRegExp(literal: string): string {
	return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

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
