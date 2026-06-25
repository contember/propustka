/**
 * Generic OIDC relying-party client. propustka federates login to ANY OpenID Connect provider —
 * Google, Auth0, Okta, Keycloak, Microsoft Entra, … — configured purely by env: an `issuer` URL plus
 * a client id/secret. Endpoints are not hardcoded; they come from the provider's discovery document
 * (`${issuer}/.well-known/openid-configuration`), so swapping IdP is a config change, not a code one.
 *
 *   1. `authorizationUrl()` — where the browser logs in (authorization-code + PKCE + state).
 *   2. `exchangeCode()`     — swap the returned code (+ PKCE verifier) for an id_token.
 *   3. `verifyIdToken()`    — verify it (signature via the discovered JWKS, issuer, audience) and
 *                             read `sub` + `email`.
 *
 * The discovery document and the JWKS resolver are injectable (the same seam `JwtValidator` uses),
 * so tests run the real protocol logic against a local key with no network. The HTTP route wiring
 * (cookies, redirects) lives in the `auth` handlers; this module is the protocol.
 */

import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose'
import { booleanField, prop, stringField } from './json'

export interface OidcConfig {
	/** The provider's issuer URL — the discovery base AND the `iss` an id_token must carry. */
	issuer: string
	clientId: string
	clientSecret: string
	/** Absolute callback URL — `${ISSUER}/auth/callback`. Must be registered with the provider. */
	redirectUri: string
	/** Space-separated scopes; defaults to `openid email profile` when empty. `openid` + `email` are required. */
	scopes: string
	/** Reject a login whose `email_verified` is not true. Default true; an IdP that omits the claim needs false. */
	requireVerifiedEmail: boolean
}

/** The verified upstream identity we resolve a principal from. */
export interface OidcIdentity {
	/** The IdP `sub` — the stable upstream subject, stored as the principal's `external_id`. */
	sub: string
	email: string
}

/** The subset of the OIDC discovery document propustka needs. */
export interface OidcMetadata {
	issuer: string
	authorizationEndpoint: string
	tokenEndpoint: string
	jwksUri: string
}

/** Injectable seams for tests: a fixed discovery doc and/or a local JWKS resolver (no network). */
export interface OidcDeps {
	metadata?: OidcMetadata
	jwks?: JWTVerifyGetKey
}

// ── PKCE ────────────────────────────────────────────────────────────────────────

/** URL-safe base64 of raw bytes (no padding) — the PKCE encoding. */
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

export class OidcClient {
	constructor(
		private readonly config: OidcConfig,
		private readonly deps: OidcDeps = {},
	) {}

	/** Where to send the browser to log in. `state` is the CSRF token; `codeChallenge` is the PKCE S256. */
	async authorizationUrl(params: { state: string; codeChallenge: string }): Promise<string> {
		const meta = await this.metadata()
		const url = new URL(meta.authorizationEndpoint)
		url.searchParams.set('client_id', this.config.clientId)
		url.searchParams.set('redirect_uri', this.config.redirectUri)
		url.searchParams.set('response_type', 'code')
		url.searchParams.set('scope', this.scopes())
		url.searchParams.set('state', params.state)
		url.searchParams.set('code_challenge', params.codeChallenge)
		url.searchParams.set('code_challenge_method', 'S256')
		return url.toString()
	}

	/**
	 * Exchange an authorization `code` (+ the PKCE `verifier`) for an id_token at the provider's
	 * token endpoint. Returns the raw id_token, or null on any failure (caller treats as auth failure).
	 */
	async exchangeCode(code: string, codeVerifier: string): Promise<string | null> {
		const meta = await this.metadata()
		const response = await fetch(meta.tokenEndpoint, {
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
	 * Verify an id_token (signature against the discovered JWKS, issuer, audience) and extract the
	 * identity. Honors `requireVerifiedEmail`. Returns null on any problem — never throws.
	 */
	async verifyIdToken(idToken: string): Promise<OidcIdentity | null> {
		let meta: OidcMetadata
		try {
			meta = await this.metadata()
		} catch {
			return null
		}
		let payload: unknown
		try {
			const result = await jwtVerify(idToken, this.jwksResolver(meta), {
				issuer: meta.issuer,
				audience: this.config.clientId,
			})
			payload = result.payload
		} catch {
			return null
		}
		const sub = stringField(payload, 'sub')
		const email = stringField(payload, 'email')
		const verified = readEmailVerified(payload)
		if (sub === undefined || email === undefined) {
			return null
		}
		// require=true → must be explicitly verified; require=false → only an EXPLICIT false is refused.
		if (this.config.requireVerifiedEmail ? verified !== true : verified === false) {
			return null
		}
		return { sub, email }
	}

	private scopes(): string {
		return this.config.scopes.trim() === '' ? 'openid email profile' : this.config.scopes
	}

	/** The provider's discovery metadata — injected (tests), else fetched once per isolate and cached. */
	async metadata(): Promise<OidcMetadata> {
		if (this.deps.metadata) {
			return this.deps.metadata
		}
		const now = Date.now() / 1000
		const cached = metadataCache.get(this.config.issuer)
		if (cached && cached.expiresAt > now) {
			return cached.metadata
		}
		const url = `${this.config.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`
		const response = await fetch(url)
		if (!response.ok) {
			throw new Error(`OIDC discovery failed for ${this.config.issuer}: ${response.status}`)
		}
		const metadata = parseMetadata(await response.json().catch(() => null))
		if (!metadata) {
			throw new Error(`OIDC discovery document at ${url} is missing required fields`)
		}
		// Per the OIDC spec the document's issuer MUST equal the issuer used to fetch it (anti-spoofing).
		if (metadata.issuer !== this.config.issuer) {
			throw new Error(`OIDC issuer mismatch: configured ${this.config.issuer}, discovered ${metadata.issuer}`)
		}
		metadataCache.set(this.config.issuer, { metadata, expiresAt: now + METADATA_TTL_SECONDS })
		return metadata
	}

	private jwksResolver(meta: OidcMetadata): JWTVerifyGetKey {
		if (this.deps.jwks) {
			return this.deps.jwks
		}
		let resolver = jwksResolvers.get(meta.jwksUri)
		if (!resolver) {
			resolver = createRemoteJWKSet(new URL(meta.jwksUri))
			jwksResolvers.set(meta.jwksUri, resolver)
		}
		return resolver
	}
}

// ── Discovery + JWKS caches (per isolate) ──────────────────────────────────────────

const METADATA_TTL_SECONDS = 3600
const metadataCache = new Map<string, { metadata: OidcMetadata; expiresAt: number }>()
/** One remote JWKS resolver per jwks_uri (jose caches the fetched keys on it). */
const jwksResolvers = new Map<string, JWTVerifyGetKey>()

function parseMetadata(doc: unknown): OidcMetadata | null {
	const issuer = stringField(doc, 'issuer')
	const authorizationEndpoint = stringField(doc, 'authorization_endpoint')
	const tokenEndpoint = stringField(doc, 'token_endpoint')
	const jwksUri = stringField(doc, 'jwks_uri')
	if (issuer === undefined || authorizationEndpoint === undefined || tokenEndpoint === undefined || jwksUri === undefined) {
		return null
	}
	return { issuer, authorizationEndpoint, tokenEndpoint, jwksUri }
}

/** Read `email_verified` as a boolean — providers send a boolean or (legacy) the string form. */
function readEmailVerified(payload: unknown): boolean | undefined {
	const asBool = booleanField(payload, 'email_verified')
	if (asBool !== undefined) {
		return asBool
	}
	const raw = prop(payload, 'email_verified')
	if (raw === 'true') {
		return true
	}
	if (raw === 'false') {
		return false
	}
	return undefined
}
