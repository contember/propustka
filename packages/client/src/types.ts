import type { DomainEvent, IssueCapabilityGrant, PrincipalListItem, PrincipalType, Scope } from '@propustka/core'

/**
 * The resolved caller's identity — who Access says you are, as the IAM Worker recorded
 * the principal. Exposed on `AuthContext` so apps can stamp domain rows (created_by,
 * activity actor, assignee) and render "signed in as …" without a second lookup. It is
 * NOT a permission surface — authorization is still `can()` / `scopedTo()`.
 *  - `id`    — the IAM principal id (UUIDv7); stable, safe to store on domain rows.
 *  - `type`  — 'user' (Access identity login) or 'service' (Access service token).
 *  - `label` — human-readable: the user's email, or the service token's name.
 */
export interface PrincipalIdentity {
	readonly id: string
	readonly type: PrincipalType
	readonly label: string
}

// ── Result surfaces ──────────────────────────────────────────────────────────
//
// Every method returns a discriminated union whose members all carry an `ok` field,
// so app code branches once on `result.ok`. The ok:true members are the rich
// `AuthContext` / `Capability` / `IssuedCapability` surfaces; the ok:false members are
// the typed failures below, each carrying the HTTP status the app should return.
//
// The ok:true surfaces are modelled as *interfaces* (not concrete classes) so that both
// the real (`permits`-backed) and fake (allow-all-except-deny) implementations satisfy a
// single shared shape without any casts — see the design note in the package README of the
// spec. The documented surface (`ok` / `can` / `scopedTo` / `audit`) is the interface.

/**
 * The authenticated, ok:true result. `can`/`scopedTo` are local & pure (no binding call);
 * only `audit` reaches the IAM Worker.
 */
export interface AuthContext {
	readonly ok: true
	/**
	 * The resolved caller identity (id / type / label), or `null` for an ANONYMOUS credential — a
	 * passthrough JWT or a standalone (no-principal) share-link/API key. For stamping domain rows and
	 * display — NOT a permission surface (authorization stays `can` / `scopedTo`, which work the same
	 * either way). Stamp `created_by` with `principal?.id ?? null`.
	 */
	readonly principal: PrincipalIdentity | null
	/**
	 * Point check: may this principal do `action` (optionally within `scope`, an opaque
	 * `{ type, value }` coordinate)? Scope-less → satisfied by GLOBAL permissions only; a
	 * scoped grant never widens into a scope-less allow.
	 */
	can(action: string, scope?: Scope): boolean
	/**
	 * Scoping: which scope values may this principal perform `action` on within `dimension`
	 * (a scope type, e.g. `'organization'`)? Scopes are flat & independent — a list is always
	 * relative to one dimension.
	 *  - `null`      → unrestricted (holds the action globally — e.g. an admin)
	 *  - `[]`        → no access within this dimension at all
	 *  - non-empty   → exactly those (opaque, app-owned) scope values
	 * Consume via `applyScope` so the empty-`IN ()` trap is handled once. `dimension` is
	 * REQUIRED — multiple scope types may coexist, so the caller must say which one.
	 */
	scopedTo(action: string, dimension: string): string[] | null
	/** Emit a domain audit event; app/principal/requestId are auto-attached. Fire-and-forget. */
	audit(event: DomainEvent): Promise<void>
}

/**
 * An anonymous redeemed capability token. Same `can` ergonomics as `AuthContext`, but
 * EXACT (action, resource) matching — no wildcards, no project scope.
 */
export interface Capability {
	readonly ok: true
	/** Exact match against the token's (action, resource) list. No wildcards. */
	can(action: string, resource: string): boolean
	/** Emit a domain audit event; capabilityTokenId + token label attached, principalId null. */
	audit(event: DomainEvent): Promise<void>
}

/** Successful `issueCapability` — plaintext token returned ONCE. */
export interface IssuedCapability {
	readonly ok: true
	/** Plaintext token — show once, never persist. */
	token: string
	/** The capability token id (safe to store/reference). */
	id: string
}

/** Successful `revokeCapability`. `revoked` is false when the token was already revoked. */
export interface RevokedCapability {
	readonly ok: true
	/** True when this call flipped the token to revoked; false if it was already revoked (idempotent). */
	revoked: boolean
}

/** Successful `listPrincipals` — the app's people directory (user principals). */
export interface PrincipalList {
	readonly ok: true
	principals: PrincipalListItem[]
}

// ── Failures ─────────────────────────────────────────────────────────────────

/** `authenticate` failure. missing/invalid → 401; unknown_principal/disabled → 403. */
export interface AuthFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled'
	status: 401 | 403
}

/** `redeemCapability` failure — a bad/expired share link reads as 404. */
export interface CapabilityFailure {
	readonly ok: false
	reason: 'unknown' | 'expired' | 'revoked' | 'exhausted'
	status: 404
}

/** `issueCapability` failure. missing/invalid → 401; unknown_principal/disabled/not_allowed → 403. */
export interface IssueFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed'
	status: 401 | 403
}

/** `revokeCapability` failure. missing/invalid → 401; unknown/disabled/not_allowed → 403; not_found → 404. */
export interface RevokeFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found'
	status: 401 | 403 | 404
}

/** `listPrincipals` failure. missing/invalid → 401; unknown_principal/disabled/not_allowed → 403. */
export interface ListPrincipalsFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed'
	status: 401 | 403
}

// ── Inputs ───────────────────────────────────────────────────────────────────

/**
 * App-supplied portion of `issueCapability` — the grants/label/expiry/maxUses. The SDK
 * fills `app` and the issuer's forwarded credentials (token/cookie/origin/requestId) from
 * the request, so app code can never self-assert the issuer.
 */
export interface IssueCapabilityRequest {
	grants: IssueCapabilityGrant[]
	label?: string
	expiresAt?: number
	maxUses?: number
}

/**
 * App-supplied portion of `issueServiceToken`. The SDK fills `app` and the issuer's forwarded
 * credentials from the request — app code can never self-assert the issuer. `permissions` are
 * inline action patterns granted to the new service principal on `scope` (the delegation check
 * requires the issuer to itself hold each there).
 */
export interface IssueServiceTokenRequest {
	label: string
	permissions: string[]
	scope?: Scope | null
	expiresAt?: number
}

/** Successful `issueServiceToken` — the `clientSecret` is returned ONCE. */
export interface IssuedServiceToken {
	readonly ok: true
	/** Access service token client id (stable; carried by the machine as `CF-Access-Client-Id`). */
	clientId: string
	/** Plaintext secret — show once, never persist. */
	clientSecret: string
	/** The IAM service principal id — the durable handle for revoke/rotate. */
	principalId: string
	/** The Access service token id. */
	tokenId: string
}

/** `issueServiceToken` failure. missing/invalid → 401; provisioning_failed → 502; rest → 403. */
export interface IssueServiceTokenFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'provisioning_failed'
	status: 401 | 403 | 502
}

/** Successful `revokeServiceToken`. `revoked` is false when the principal was already disabled. */
export interface RevokedServiceToken {
	readonly ok: true
	revoked: boolean
}

/** `revokeServiceToken` failure. missing/invalid → 401; not_found → 404; rest → 403. */
export interface RevokeServiceTokenFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found'
	status: 401 | 403 | 404
}

/** Successful `rotateServiceToken` — new `clientSecret` ONCE; the client_id is unchanged. */
export interface RotatedServiceToken {
	readonly ok: true
	clientId: string
	clientSecret: string
	tokenId: string
}

/** `rotateServiceToken` failure. missing/invalid → 401; not_found → 404; provisioning_failed → 502; rest → 403. */
export interface RotateServiceTokenFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found' | 'provisioning_failed'
	status: 401 | 403 | 404 | 502
}
