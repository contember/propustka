/**
 * Google OIDC relying-party client. propustka now federates login to Google directly (instead of
 * riding on Cloudflare Access's SSO), so it implements the authorization-code + PKCE flow:
 *
 *   1. `authorizationUrl()` — where the browser is sent to log in (with a PKCE challenge + state).
 *   2. `exchangeCode()`     — swap the returned code (+ PKCE verifier) for an id_token at Google.
 *   3. `verifyIdToken()`    — cryptographically verify that id_token and read `sub` + `email`.
 *
 * Only Google is supported (the chosen IdP). The JWKS resolver is injectable — the same seam
 * `JwtValidator` uses — so tests verify locally-signed id_tokens without network. The HTTP route
 * wiring (cookies, redirects) lives in `admin`/`auth` handlers; this module is the protocol.
 */

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose'
import { booleanField, prop, stringField } from './json'

const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth'
const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
const JWKS_URI = 'https://www.googleapis.com/oauth2/v3/certs'
/** Google issues tokens under both forms; accept either. */
const GOOGLE_ISSUERS = ['https://accounts.google.com', 'accounts.google.com']

export interface OidcConfig {
	clientId: string
	clientSecret: string
	/** Absolute callback URL — `${ISSUER}/auth/callback`. Must match a Google-registered redirect URI. */
	redirectUri: string
}

/** The verified upstream identity we resolve a principal from. */
export interface GoogleIdentity {
	/** Google `sub` — the stable upstream subject, stored as the principal's `external_id`. */
	sub: string
	email: string
}

// ── PKCE ────────────────────────────────────────────────────────────────────────

/** URL-safe base64 of raw bytes (no padding) — the PKCE + token encoding. */
function base64url(bytes: Uint8Array): string {
	let binary = ''
	for (const b of bytes) {
		binary += String.fromCharCode(b)
	}
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

/** A random URL-safe token (default 32 bytes / 256 bits) — PKCE verifier, state nonce, session id. */
export function randomToken(bytes = 32): string {
	const buf = new Uint8Array(bytes)
	crypto.getRandomValues(buf)
	return base64url(buf)
}

/** Generate a PKCE pair: a high-entropy `verifier` and its S256 `challenge`. */
export async function generatePkce(): Promise<{ verifier: string; challenge: string }> {
	const verifier = randomToken(32)
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
	return { verifier, challenge: base64url(new Uint8Array(digest)) }
}

// ── The client ───────────────────────────────────────────────────────────────────

export class GoogleOidc {
	private readonly jwks: JWTVerifyGetKey

	/**
	 * `jwks` defaults to Google's remote cert set (cached per-isolate by jose); tests inject a
	 * local resolver to verify id_tokens signed with their own key — production never overrides it.
	 */
	constructor(
		private readonly config: OidcConfig,
		jwks: JWTVerifyGetKey = createRemoteJWKSet(new URL(JWKS_URI)),
	) {
		this.jwks = jwks
	}

	/** Where to send the browser to log in. `state` is the CSRF token; `codeChallenge` is the PKCE S256. */
	authorizationUrl(params: { state: string; codeChallenge: string }): string {
		const url = new URL(AUTH_ENDPOINT)
		url.searchParams.set('client_id', this.config.clientId)
		url.searchParams.set('redirect_uri', this.config.redirectUri)
		url.searchParams.set('response_type', 'code')
		url.searchParams.set('scope', 'openid email profile')
		url.searchParams.set('state', params.state)
		url.searchParams.set('code_challenge', params.codeChallenge)
		url.searchParams.set('code_challenge_method', 'S256')
		// online: no refresh token needed (our own session is the long-lived credential).
		url.searchParams.set('access_type', 'online')
		url.searchParams.set('prompt', 'select_account')
		return url.toString()
	}

	/**
	 * Exchange an authorization `code` (+ the PKCE `verifier`) for an id_token at Google's token
	 * endpoint. Returns the raw id_token, or null on any failure (caller treats as auth failure).
	 */
	async exchangeCode(code: string, codeVerifier: string): Promise<string | null> {
		const response = await fetch(TOKEN_ENDPOINT, {
			method: 'POST',
			headers: { 'content-type': 'application/x-www-form-urlencoded' },
			body: this.tokenRequestBody(code, codeVerifier).toString(),
		})
		if (!response.ok) {
			return null
		}
		const json: unknown = await response.json().catch(() => null)
		return stringField(json, 'id_token') ?? null
	}

	/** The x-www-form-urlencoded body for the code→token exchange (separated so it's unit-testable). */
	tokenRequestBody(code: string, codeVerifier: string): URLSearchParams {
		return new URLSearchParams({
			grant_type: 'authorization_code',
			code,
			client_id: this.config.clientId,
			client_secret: this.config.clientSecret,
			redirect_uri: this.config.redirectUri,
			code_verifier: codeVerifier,
		})
	}

	/**
	 * Verify an id_token (signature, issuer, audience) and extract the identity. Requires a
	 * verified email. Returns null on any problem — never throws.
	 */
	async verifyIdToken(idToken: string): Promise<GoogleIdentity | null> {
		let payload: unknown
		try {
			const result = await jwtVerify(idToken, this.jwks, { issuer: GOOGLE_ISSUERS, audience: this.config.clientId })
			payload = result.payload
		} catch {
			return null
		}
		const sub = stringField(payload, 'sub')
		const email = stringField(payload, 'email')
		// Google sends email_verified as a boolean (sometimes the string "true" via some flows).
		const emailVerified = booleanField(payload, 'email_verified') ?? prop(payload, 'email_verified') === 'true'
		if (sub === undefined || email === undefined || !emailVerified) {
			return null
		}
		return { sub, email }
	}
}
