/**
 * The propustka-issued token contract — the SECOND thing (after `IamRpc`) that must not drift
 * between the Worker and the SDK.
 *
 * Background: today a request is authorized by the Worker resolving a Cloudflare Access JWT on
 * every call over RPC (the CF token carries only identity, so authz needs a round-trip). When
 * propustka issues its OWN token it can embed the already-resolved permission set, and the SDK
 * authorizes LOCALLY — no per-request round-trip. This module is the wire shape of that token:
 *
 *   - the Worker BUILDS claims here and signs them (`buildAccessClaims`);
 *   - the SDK verifies the signature with jose, then PARSES the payload back into typed claims
 *     here (`parseAccessClaims`) — structurally, so it reads them without an `as` cast — and maps a
 *     principal-bound token into the `ResolvedPrincipal` the existing `AuthContext` consumes.
 *
 * ONE shape, no `kind` discriminator (see `propustka-native-spec.md`). Every token carries
 * `perms: PermissionEntry[]` (authorized via `permits` — scopes + wildcards) and an OPTIONAL
 * principal (`ptype`): present means the token is bound to a user/service principal; absent means an
 * anonymous credential (a share link / standalone JWT), whose `perms` are narrow scoped entries and
 * whose audit actor is `label`. `sub` is the subject id either way — a principal id when bound, else
 * the issuing credential/token id.
 *
 * Pure: no jose, no I/O. Signing/verifying (key material) stays in the packages that own it.
 */

import { numberField, prop, stringField } from './json'
import type { ResolvedPrincipal } from './rpc'
import type { PermissionEntry, PermissionSource, PrincipalType, Scope } from './types'

// ── Names & knobs on the wire (both sides agree) ───────────────────────────────

/** Long-lived opaque SSO session id; propustka sets it on its parent cookie domain at login. */
export const SESSION_COOKIE = 'px_session'
/** Short-lived per-app access JWT; a host-only cookie the app's middleware sets and reads. */
export const TOKEN_COOKIE = 'px_token'
/** Prefix marking a propustka opaque credential (API key / share link), e.g. `Bearer px_<random>`. */
export const API_KEY_PREFIX = 'px_'

/** Signing algorithm propustka issues with and the SDK verifies (ECDSA P-256 — compact, ubiquitous). */
export const TOKEN_ALG = 'ES256'

/** Default per-app access-token lifetime. Revocation/role changes take effect within this. */
export const DEFAULT_TOKEN_TTL_SECONDS = 300
/**
 * Hard cap on a `issueJwt` passthrough token's lifetime. A passthrough JWT is NOT revocable (no
 * stored row), so its TTL is its whole security window — bounded here (24 h) regardless of request.
 */
export const MAX_PASSTHROUGH_TTL_SECONDS = 24 * 60 * 60
/**
 * The SDK refreshes an access token this many seconds BEFORE it expires, so a request never rides a
 * token that expires mid-flight. Must be < the token TTL.
 */
export const TOKEN_REFRESH_SKEW_SECONDS = 30

// ── Claim shape (one, no discriminator) ────────────────────────────────────────

/**
 * The propustka access token. `perms` is always present (matched via `permits`); `ptype` is present
 * only when `sub` is a principal. `label` is the audit actor — the principal's label when bound, the
 * credential/jwt label otherwise (or null).
 */
export interface AccessTokenClaims {
	/** Issuer — propustka's own origin (e.g. `https://propustka.example.com`). */
	iss: string
	/** The app id this token is scoped to. The SDK REJECTS a token whose `aud` is not its app. */
	aud: string
	/** Subject id: a principal id when `ptype` is set, else the issuing credential/token id. */
	sub: string
	/** Issued-at (unix seconds). */
	iat: number
	/** Expiry (unix seconds). */
	exp: number
	/** Resolved/effective permissions; `can(action, scope?)` = `permits(perms, action, scope)`. */
	perms: PermissionEntry[]
	/** Present only when the token is bound to a principal (`sub` is that principal). */
	ptype?: PrincipalType
	/** Audit actor label — the principal's label, or the credential/jwt label, or null (anonymous). */
	label: string | null
}

// ── Public JWKS (the SDK fetches this once, then verifies tokens locally) ───────
//
// Transport is the IAM service binding (`getJwks()` RPC), NOT a public HTTPS URL: app↔IAM is
// RPC over the binding, which never traverses the Access edge — so the SDK reaches the key set
// even while propustka's own hostname is still gated by Cloudflare Access. The Worker also
// serves the standard `/.well-known/jwks.json`, for when Access is gone. Both emit this shape.

/** A published public signing key (EC P-256 / ES256). A jose-compatible JWK subset. */
export interface PublicJwk {
	kty: string
	crv?: string
	x?: string
	y?: string
	kid?: string
	alg?: string
	use?: string
}

/** The public key set the SDK feeds to a local JWKS verifier. */
export interface Jwks {
	keys: PublicJwk[]
}

// ── Build (Worker side, pre-sign) ──────────────────────────────────────────────

export interface AccessTokenParams {
	/** Issuer (propustka origin). */
	iss: string
	/** App id this token is for (becomes `aud`). */
	app: string
	/** Subject id (becomes `sub`) — a principal id when `type` is given, else a credential/token id. */
	subject: string
	/** Principal type — omit for an anonymous credential (share link / standalone JWT). */
	type?: PrincipalType
	/** Audit actor label, or null for an unlabeled anonymous token. */
	label: string | null
	permissions: PermissionEntry[]
	issuedAt: number
	expiresAt: number
}

/** Assemble the claim object for an access token. Pure — the caller signs the result. */
export function buildAccessClaims(params: AccessTokenParams): AccessTokenClaims {
	const claims: AccessTokenClaims = {
		iss: params.iss,
		aud: params.app,
		sub: params.subject,
		iat: params.issuedAt,
		exp: params.expiresAt,
		perms: params.permissions,
		label: params.label,
	}
	if (params.type !== undefined) {
		claims.ptype = params.type
	}
	return claims
}

// ── Parse (SDK side, post-verify) ──────────────────────────────────────────────

/**
 * Narrow a verified JWT payload into typed access-token claims WITHOUT trusting its shape. jose has
 * already checked the signature, `exp`, and `aud`; this validates the custom claims structurally so
 * the SDK reads them without an `as` cast. Returns null on any malformed claim shape.
 */
export function parseAccessClaims(payload: unknown): AccessTokenClaims | null {
	const iss = stringField(payload, 'iss')
	const aud = stringField(payload, 'aud')
	const sub = stringField(payload, 'sub')
	const iat = numberField(payload, 'iat')
	const exp = numberField(payload, 'exp')
	const perms = parsePermissionEntries(prop(payload, 'perms'))
	const label = parseNullableString(prop(payload, 'label'))
	const ptype = parseOptionalPrincipalType(prop(payload, 'ptype'))
	if (iss === undefined || aud === undefined || sub === undefined || iat === undefined || exp === undefined) {
		return null
	}
	if (perms === null || label === undefined || ptype === undefined) {
		return null
	}
	const claims: AccessTokenClaims = { iss, aud, sub, iat, exp, perms, label }
	if (ptype !== null) {
		claims.ptype = ptype
	}
	return claims
}

/**
 * Map a verified PRINCIPAL-bound access token into the `ResolvedPrincipal` the existing
 * `AuthContext` consumes. Returns null for an anonymous token (no `ptype`) — the caller handles
 * the anonymous case separately.
 */
export function accessClaimsToResolved(claims: AccessTokenClaims, requestId: string): ResolvedPrincipal | null {
	if (claims.ptype === undefined) {
		return null
	}
	return {
		id: claims.sub,
		type: claims.ptype,
		label: claims.label ?? claims.sub,
		permissions: claims.perms,
		requestId,
	}
}

// ── Structural parsers (no `as`) ───────────────────────────────────────────────

/** Read `ptype`: a valid principal type, explicit-absent (→ null), or malformed (→ undefined). */
function parseOptionalPrincipalType(value: unknown): PrincipalType | null | undefined {
	if (value === undefined || value === null) {
		return null
	}
	return value === 'user' || value === 'service' ? value : undefined
}

/** Accept a string or explicit-null/absent (→ null); reject any other type (→ undefined). */
function parseNullableString(value: unknown): string | null | undefined {
	if (value === null || value === undefined) {
		return null
	}
	return typeof value === 'string' ? value : undefined
}

function parseScope(value: unknown): Scope | null | undefined {
	if (value === null) {
		return null
	}
	const type = stringField(value, 'type')
	const scopeValue = stringField(value, 'value')
	if (type === undefined || scopeValue === undefined) {
		return undefined
	}
	return { type, value: scopeValue }
}

/** Validate `source` against the union — our own token, but read without `as`. */
function parseSource(value: unknown): PermissionSource | null {
	if (value === 'grant' || value === 'bootstrap') {
		return value
	}
	if (typeof value === 'string' && value.startsWith('group:')) {
		return `group:${value.slice('group:'.length)}`
	}
	return null
}

function parsePermissionEntries(value: unknown): PermissionEntry[] | null {
	if (!Array.isArray(value)) {
		return null
	}
	const out: PermissionEntry[] = []
	for (const item of value) {
		const action = stringField(item, 'action')
		const scope = parseScope(prop(item, 'scope'))
		const source = parseSource(prop(item, 'source'))
		if (action === undefined || scope === undefined || source === null) {
			return null
		}
		out.push({ action, scope, source })
	}
	return out
}
