/**
 * The propustka-issued token contract — the SECOND thing (after `IamRpc`) that must not drift
 * between the Worker and the SDK.
 *
 * Background: today a request is authorized by the Worker resolving a Cloudflare Access JWT on
 * every call over RPC (the CF token carries only identity, so authz needs a round-trip). When
 * propustka issues its OWN token it can embed the already-resolved permission set, and the SDK
 * authorizes LOCALLY — no per-request round-trip. This module is the wire shape of that token:
 *
 *   - the Worker BUILDS claims here and signs them (`buildPrincipalClaims` / `buildCapabilityClaims`);
 *   - the SDK verifies the signature with jose, then PARSES the payload back into typed claims
 *     here (`parseTokenClaims`) — structurally, so it reads them without an `as` cast — and maps a
 *     principal token straight into the `ResolvedPrincipal` the existing `AuthContext` consumes.
 *
 * Two token kinds mirror the two existing auth shapes:
 *   - `principal`  — a user or service principal, carrying the resolved `PermissionEntry[]`
 *     (wildcard `can(action, scope?)`). Backs the session cookie AND API-key paths.
 *   - `capability` — an anonymous share-link grant: exact-match `(action, resource)` pairs, no
 *     identity. Backs the public share-link path.
 *
 * Pure: no jose, no I/O. Signing/verifying (key material) stays in the packages that own it.
 */

import { numberField, prop, stringField } from './json'
import type { ResolvedPrincipal } from './rpc'
import type { PermissionEntry, PermissionSource, PrincipalType, Scope } from './types'

// ── Names & knobs on the wire (both sides agree) ───────────────────────────────

/** Long-lived opaque SSO session id; propustka sets it on its parent cookie domain at login. */
export const SESSION_COOKIE = 'px_session'
/** Short-lived per-app permission JWT; a host-only cookie the app's middleware sets and reads. */
export const TOKEN_COOKIE = 'px_token'
/** Prefix marking a propustka API key, presented as `Authorization: Bearer px_<random>`. */
export const API_KEY_PREFIX = 'px_'

/** Signing algorithm propustka issues with and the SDK verifies (ECDSA P-256 — compact, ubiquitous). */
export const TOKEN_ALG = 'ES256'

/** Default per-app permission-token lifetime. Revocation/role changes take effect within this. */
export const DEFAULT_TOKEN_TTL_SECONDS = 300
/**
 * The SDK refreshes a permission token this many seconds BEFORE it expires, so a request never
 * rides a token that expires mid-flight. Must be < DEFAULT_TOKEN_TTL_SECONDS.
 */
export const TOKEN_REFRESH_SKEW_SECONDS = 30

// ── Claim shapes ───────────────────────────────────────────────────────────────

export type TokenKind = 'principal' | 'capability'

/** Standard claims every propustka token carries. */
interface BaseClaims {
	/** Issuer — propustka's own origin (e.g. `https://propustka.example.com`). */
	iss: string
	/** The app id this token is scoped to. The SDK REJECTS a token whose `aud` is not its app. */
	aud: string
	/** principal id (kind=`principal`) or capability token id (kind=`capability`). */
	sub: string
	/** Issued-at (unix seconds). */
	iat: number
	/** Expiry (unix seconds). */
	exp: number
}

/** A principal-backed token — carries the resolved permission set so the SDK authorizes locally. */
export interface PrincipalTokenClaims extends BaseClaims {
	kind: 'principal'
	ptype: PrincipalType
	label: string
	perms: PermissionEntry[]
}

/** One exact-match capability the share-link token confers. */
export interface CapabilityClaim {
	action: string
	resource: string
}

/** An anonymous share-link token — exact-match `(action, resource)` grants, no identity. */
export interface CapabilityTokenClaims extends BaseClaims {
	kind: 'capability'
	label: string | null
	caps: CapabilityClaim[]
}

export type PropustkaTokenClaims = PrincipalTokenClaims | CapabilityTokenClaims

// ── Build (Worker side, pre-sign) ──────────────────────────────────────────────

export interface PrincipalTokenParams {
	/** Issuer (propustka origin). */
	iss: string
	/** App id this token is for (becomes `aud`). */
	app: string
	principalId: string
	type: PrincipalType
	label: string
	permissions: PermissionEntry[]
	issuedAt: number
	expiresAt: number
}

/** Assemble the claim object for a principal token. Pure — the caller signs the result. */
export function buildPrincipalClaims(params: PrincipalTokenParams): PrincipalTokenClaims {
	return {
		iss: params.iss,
		aud: params.app,
		sub: params.principalId,
		iat: params.issuedAt,
		exp: params.expiresAt,
		kind: 'principal',
		ptype: params.type,
		label: params.label,
		perms: params.permissions,
	}
}

export interface CapabilityTokenParams {
	iss: string
	app: string
	/** The capability token id (becomes `sub`). */
	tokenId: string
	label: string | null
	caps: CapabilityClaim[]
	issuedAt: number
	expiresAt: number
}

/** Assemble the claim object for a capability (share-link) token. Pure — the caller signs it. */
export function buildCapabilityClaims(params: CapabilityTokenParams): CapabilityTokenClaims {
	return {
		iss: params.iss,
		aud: params.app,
		sub: params.tokenId,
		iat: params.issuedAt,
		exp: params.expiresAt,
		kind: 'capability',
		label: params.label,
		caps: params.caps,
	}
}

// ── Parse (SDK side, post-verify) ──────────────────────────────────────────────

/**
 * Narrow a verified JWT payload into typed propustka claims WITHOUT trusting its shape. jose has
 * already checked the signature, `exp`, and `aud`; this validates the custom claims structurally so
 * the SDK reads them without an `as` cast. Returns null on any malformed/unknown claim shape.
 */
export function parseTokenClaims(payload: unknown): PropustkaTokenClaims | null {
	const iss = stringField(payload, 'iss')
	const aud = stringField(payload, 'aud')
	const sub = stringField(payload, 'sub')
	const iat = numberField(payload, 'iat')
	const exp = numberField(payload, 'exp')
	if (iss === undefined || aud === undefined || sub === undefined || iat === undefined || exp === undefined) {
		return null
	}
	const base: BaseClaims = { iss, aud, sub, iat, exp }

	const kind = stringField(payload, 'kind')
	if (kind === 'principal') {
		const ptype = parsePrincipalType(prop(payload, 'ptype'))
		const label = stringField(payload, 'label')
		const perms = parsePermissionEntries(prop(payload, 'perms'))
		if (ptype === null || label === undefined || perms === null) {
			return null
		}
		return { ...base, kind: 'principal', ptype, label, perms }
	}
	if (kind === 'capability') {
		const label = parseNullableString(prop(payload, 'label'))
		const caps = parseCapabilityClaims(prop(payload, 'caps'))
		if (label === undefined || caps === null) {
			return null
		}
		return { ...base, kind: 'capability', label, caps }
	}
	return null
}

/** Map a verified principal token into the `ResolvedPrincipal` the existing `AuthContext` consumes. */
export function principalClaimsToResolved(claims: PrincipalTokenClaims, requestId: string): ResolvedPrincipal {
	return {
		id: claims.sub,
		type: claims.ptype,
		label: claims.label,
		permissions: claims.perms,
		requestId,
	}
}

// ── Structural parsers (no `as`) ───────────────────────────────────────────────

function parsePrincipalType(value: unknown): PrincipalType | null {
	return value === 'user' || value === 'service' ? value : null
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

function parseCapabilityClaims(value: unknown): CapabilityClaim[] | null {
	if (!Array.isArray(value)) {
		return null
	}
	const out: CapabilityClaim[] = []
	for (const item of value) {
		const action = stringField(item, 'action')
		const resource = stringField(item, 'resource')
		if (action === undefined || resource === undefined) {
			return null
		}
		out.push({ action, resource })
	}
	return out
}
