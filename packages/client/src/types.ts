import type { DomainEvent, IssueKeyServiceSpec, KeyGrant, PrincipalListItem, PrincipalType, Scope } from '@propustka/core'

/**
 * The resolved caller's identity — who Access says you are, as the IAM Worker recorded
 * the principal. Exposed on `AuthContext` so apps can stamp domain rows (created_by,
 * activity actor, assignee) and render "signed in as …" without a second lookup. It is
 * NOT a permission surface — authorization is still `can()` / `scopedTo()`.
 *  - `id`    — the IAM principal id (UUIDv7); stable, safe to store on domain rows.
 *  - `type`  — 'user' (a human identity) or 'service' (a machine principal / API key).
 *  - `label` — human-readable: the user's email, or the service principal's name.
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
// `AuthContext` / `IssuedKey` / `IssuedJwt` surfaces; the ok:false members are
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

/** Successful `issueKey` — the plaintext `px_` token returned ONCE; `id` is the durable revoke handle. */
export interface IssuedKey {
	readonly ok: true
	/** Plaintext `px_` token — show once, never persist. Carry as a bearer or a share-link path token. */
	token: string
	/** The credential id (safe to store/reference; pass to `revokeKey`). */
	id: string
	/**
	 * The principal the key is bound to — the freshly-created service principal (`service` mode) or the
	 * issuer's own id (self-bind); absent for a standalone (anonymous) share link.
	 */
	principalId?: string
}

/** Successful `issueJwt` — the signed passthrough token returned ONCE (audit-only, not revocable). */
export interface IssuedJwt {
	readonly ok: true
	/** The signed JWT — carry it as `Authorization: Bearer`. Verified locally by the app's SDK. */
	token: string
	/** Expiry (unix seconds). */
	expiresAt: number
	/** The token's audit reference (there is no DB row to revoke). */
	id: string
}

/** Successful `revokeKey`. `revoked` is false when the credential was already revoked. */
export interface RevokedKey {
	readonly ok: true
	/** True when this call flipped the credential to revoked; false if it was already revoked (idempotent). */
	revoked: boolean
}

/** Successful `listPrincipals` — the app's people directory (user principals). */
export interface PrincipalList {
	readonly ok: true
	principals: PrincipalListItem[]
}

// ── Failures ─────────────────────────────────────────────────────────────────

/** `issueKey` / `issueJwt` failure. missing/invalid → 401; unknown_principal/disabled/not_allowed → 403. */
export interface IssueFailure {
	readonly ok: false
	reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed'
	status: 401 | 403
}

/** `revokeKey` failure. missing/invalid → 401; unknown/disabled/not_allowed → 403; not_found → 404. */
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
 * App-supplied portion of `issueKey` — an opaque, stored, revocable `px_` credential (API key /
 * share link). The SDK fills `app` and the issuer's forwarded credential (the caller's `px_token` /
 * `px_` key + requestId) from the request, so app code can never self-assert the issuer.
 */
export interface IssueKeyRequest {
	/**
	 * Create a NEW machine (service) principal and bind the key to it — the folded service-token
	 * path. The issuer must hold every `permissions` action on `scope`. When set, `principalId` /
	 * `permissions` (the bind / standalone modes) are ignored.
	 */
	service?: IssueKeyServiceSpec
	/**
	 * Bind to a principal (the credential then carries that principal's LIVE perms; inline
	 * `permissions` downscope it). v1: only the issuer's OWN id. Omit for a standalone share link.
	 */
	principalId?: string
	/** Inline grants — the frozen set (standalone share link) and/or a downscope restriction (bound). */
	permissions?: KeyGrant[]
	label?: string
	/** Absolute credential expiry (unix seconds); omitted = no expiry. */
	expiresAt?: number
}

/**
 * App-supplied portion of `issueJwt` — a stateless passthrough access token (audit-only, TTL-bounded,
 * NOT revocable). The SDK fills `app` and the issuer's forwarded credential from the request.
 */
export interface IssueJwtRequest {
	/** Inline grants the passthrough token carries (frozen at issue). */
	permissions: KeyGrant[]
	label?: string
	/** Requested lifetime (seconds); capped by the server. Defaults to the standard token TTL. */
	ttl?: number
}
