import type { DomainEvent, IssueCapabilityGrant } from '@propustka/core'

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
	 * Point check: may this principal do `action` (optionally on `scope.project`)?
	 * Scope-less → satisfied by GLOBAL permissions only; a project-scoped grant never
	 * widens into a scope-less allow.
	 */
	can(action: string, scope?: { project?: string }): boolean
	/**
	 * Scoping: which project ids may this principal perform `action` on?
	 *  - `null`      → unrestricted (holds the action globally — e.g. an admin)
	 *  - `[]`        → no project access at all
	 *  - non-empty   → exactly those project ids
	 * Consume via `applyScope` so the empty-`IN ()` trap is handled once. `dimension`
	 * defaults to `'project'` and is forward-looking only (v1 has a single scope dimension).
	 */
	scopedTo(action: string, dimension?: string): string[] | null
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
