import type { Jwks } from './token'
import type { PermissionEntry, PrincipalType, Scope } from './types'

// ── propustka-native session auth (mint a per-app permission token from an SSO session) ──
//
// The SDK middleware presents the browser's opaque SSO session cookie; the Worker validates it,
// resolves the principal's permissions FOR THE CALLING APP, and signs a short-lived per-app
// permission token. The SDK then verifies that token LOCALLY (via `getJwks`) on every request —
// no per-request round-trip. `app` is self-asserted, but it is harmless: permissions are resolved
// server-side per app and the token's `aud` binds it to that app (a token minted for app X is
// rejected by any other app), so an app can only ever obtain its OWN permissions.

export interface MintTokenInput {
	/** The app requesting a permission token (the SDK bakes this into its constructor). */
	app: string
	/** The opaque SSO session cookie value (px_session); null when the browser has no session. */
	session: string | null
	requestId: string
}

export type MintTokenResult =
	/** `expiresAt` (unix seconds) lets the SDK refresh ahead of expiry. */
	| { ok: true; token: string; expiresAt: number }
	| { ok: false; reason: 'no_session' | 'invalid_session' | 'unknown_principal' | 'disabled' }

// ── propustka-native key auth (mint an access token from an opaque `px_` credential) ──
//
// The other front over the same resolve→sign core as `mintToken`: the SDK presents an opaque
// credential (an API key as a bearer, or a share-link path token) and the Worker resolves its
// EFFECTIVE permissions (principal-bound → live; anonymous → frozen inline grants) and signs an
// access token the SDK then verifies locally. `app` is self-asserted but harmless — the token's
// `aud` binds it and permissions are resolved server-side per app.

export interface MintFromKeyInput {
	/** The app requesting the token (the SDK bakes this into its constructor). */
	app: string
	/** The opaque `px_` credential (bearer / path token). */
	key: string
	requestId: string
}

export type MintFromKeyResult =
	| { ok: true; token: string; expiresAt: number }
	| { ok: false; reason: 'invalid_key' | 'unknown_principal' | 'disabled' }

// ── Issuing credentials (issueKey) and passthrough tokens (issueJwt) ──────────────
//
// `issueKey` mints an opaque, stored, revocable `px_` credential; `issueJwt` signs a stateless
// passthrough access token (audit-only, TTL-bounded, not revocable). Both are DELEGATED: the issuer
// is resolved server-side from the forwarded credentials and may only grant what it itself holds.

/** One grant on a `px_` credential / passthrough token — an action pattern + optional scope. */
export interface KeyGrant {
	action: string
	/** Omitted/null = global (the issuer must hold the action globally). */
	scope?: Scope | null
}

/**
 * Create a NEW service (machine) principal and bind the key to it — the folded `issueServiceToken`.
 * The issuer must hold every `permissions` action on `scope` (the same delegation rule as a grant).
 */
export interface IssueKeyServiceSpec {
	/** Display label for the new service principal + the credential. */
	label: string
	/** Inline action patterns granted to the new service principal; delegation-checked on `scope`. */
	permissions: string[]
	/** Scope the grant + the delegation check apply to; omitted/null → global. */
	scope?: Scope | null
}

export interface IssueKeyInput {
	app: string
	/**
	 * The propustka-native credential the ISSUER is resolved from server-side (never self-asserted):
	 * a `px_token` access JWT (verified against propustka's signing keys) or a `px_` key. Null = absent.
	 */
	credential: string | null
	requestId: string
	/**
	 * Create a NEW machine principal and bind the key to it (the folded `issueServiceToken`). When set,
	 * `principalId` / `permissions` (the bind / standalone modes) are ignored.
	 */
	service?: IssueKeyServiceSpec
	/**
	 * Bind to a principal (the credential then carries that principal's LIVE perms; inline
	 * `permissions` downscope it). v1: only the issuer's OWN id. Omit for a standalone credential.
	 */
	principalId?: string
	/** Inline grants — the frozen set (standalone) and/or a downscope restriction (bound). */
	permissions?: KeyGrant[]
	label?: string
	/** Absolute credential expiry (unix seconds); NULL = no expiry. */
	expiresAt?: number
}

export type IssueKeyResult =
	/**
	 * Plaintext `px_` token returned ONCE; `id` is the credential's stable handle (revoke). `principalId`
	 * is present when the key is bound to a principal (a `service` create or a self-bind), absent for a
	 * standalone (anonymous) credential.
	 */
	| { ok: true; token: string; id: string; principalId?: string }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' }

export interface IssueJwtInput {
	app: string
	/** The propustka-native credential the ISSUER is resolved from (px_token / px_ key); null = absent. */
	credential: string | null
	requestId: string
	/** Inline grants the passthrough token carries (frozen at issue). */
	permissions: KeyGrant[]
	label?: string
	/** Requested lifetime (seconds); capped by the server. Defaults to the standard token TTL. */
	ttl?: number
}

export type IssueJwtResult =
	/** The signed passthrough token returned ONCE; `id` is its audit reference (no DB row to revoke). */
	| { ok: true; token: string; expiresAt: number; id: string }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' }

/**
 * A resolved caller identity + its frozen permission snapshot. Produced by `accessClaimsToResolved`
 * from a verified access token (`token.ts`); consumed where a principal's resolved perms are needed
 * as a plain serializable value.
 */
export interface ResolvedPrincipal {
	id: string
	type: PrincipalType
	label: string
	permissions: PermissionEntry[]
	requestId: string
}

export interface AuditInput {
	app: string
	requestId: string
	/** NULL for an anonymous-credential event (a share link / passthrough JWT has no principal). */
	principalId: string | null
	/** Snapshot — survives principal deletion (the credential/token label for anonymous events). */
	principalLabel: string
	/** Set for an anonymous-credential event — the issuing credential / passthrough-token id. */
	credentialId?: string
	action: string
	resourceType: string
	resourceId?: string
	diff?: unknown
	metadata?: unknown
}

export interface RevokeKeyInput {
	app: string
	/** The propustka-native credential the CALLER (authorizer) is resolved from; null = absent. */
	credential: string | null
	requestId: string
	/** The credential id (the `id` returned by `issueKey`), NOT the plaintext `px_` token. */
	id: string
}

export type RevokeKeyResult =
	/** `revoked` is false when the credential was already revoked (idempotent). */
	| { ok: true; revoked: boolean }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found' }

// ── List principals (the app's people directory) ───────────────────────────────
//
// A read-only enumeration of the USER principals who can access an app — its people
// directory. Apps consume it for things propustka isn't the authority on but needs the
// roster for: an assignee picker, an actor/owner label list. The caller is resolved from
// the forwarded Access credentials and the listed app is the aud-VERIFIED app — an operator
// can only enumerate the roster of an app it itself authenticates to (never a self-asserted
// app), so there is no cross-app leak. Services are excluded (machines aren't assignable
// people); each item carries `disabled` so the consumer can grey-out/hide deactivated users.

export interface ListPrincipalsInput {
	/** Self-asserted caller app id; superseded by the credential's aud on a valid `px_token`. */
	app: string
	/** The propustka-native credential the CALLER is resolved from (px_token / px_ key); null = absent. */
	credential: string | null
	requestId: string
}

export interface PrincipalListItem {
	/** IAM principal id (UUIDv7) — stable, safe to store on domain rows (assignee/actor). */
	id: string
	type: PrincipalType
	/** Human-readable: the user's email. */
	label: string
	/** The user's email (users always have one; null only defensively). */
	email: string | null
	/** True when the principal is soft-disabled (kept listable so labels still resolve). */
	disabled: boolean
}

export type ListPrincipalsResult =
	| { ok: true; principals: PrincipalListItem[] }
	/** `not_allowed` when the caller has no verified app / no permission on it (a zero-grant user). */
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' }

/**
 * The RPC contract. The Worker's `WorkerEntrypoint` `implements IamRpc`; the SDK types its
 * binding as `Service<IamRpc>` (so the SDK never imports the Worker). Methods return plain
 * serializable objects (RPC-friendly).
 */
export interface IamRpc {
	/**
	 * Mint a short-lived, per-app permission token from the browser's SSO session — the
	 * propustka-native auth path. The SDK middleware calls this only when its cached permission
	 * token is missing/near-expiry (≈ once per TTL), NOT per request: every other request verifies
	 * the cached token locally against `getJwks`.
	 */
	mintToken(input: MintTokenInput): Promise<MintTokenResult>
	/**
	 * Mint a per-app access token from an opaque `px_` credential (API key / share link) — the other
	 * front over the same resolve→sign core as `mintToken`. Called by the SDK middleware once per TTL
	 * when a request carries a `px_` bearer/path credential; every other request verifies the cached
	 * token locally. Fails closed (`invalid_key`/`unknown_principal`/`disabled`).
	 */
	mintFromKey(input: MintFromKeyInput): Promise<MintFromKeyResult>
	/**
	 * Mint an opaque, stored, revocable `px_` credential (API key / share link). Delegated: the issuer
	 * is resolved from the forwarded credentials and may only grant what it holds. Returns the
	 * plaintext token ONCE; `id` is the durable handle for revoke.
	 */
	issueKey(input: IssueKeyInput): Promise<IssueKeyResult>
	/**
	 * Sign a stateless passthrough access token (audit-only, TTL-bounded, NOT revocable). Delegated
	 * like `issueKey`. The caller carries the returned JWT directly; apps verify it locally with no
	 * propustka round-trip.
	 */
	issueJwt(input: IssueJwtInput): Promise<IssueJwtResult>
	/**
	 * The public signing key set. The SDK fetches it ONCE per isolate (cached) over the binding —
	 * which never traverses the Access edge — then verifies every permission token locally.
	 */
	getJwks(): Promise<Jwks>
	audit(event: AuditInput): Promise<void>
	/**
	 * List the USER principals who can access the caller's app (its people directory). The caller
	 * is resolved from the forwarded Access credentials and the app is the aud-VERIFIED app — so an
	 * operator only ever sees its own app's roster. Authorized for any member that holds at least
	 * one permission on the app; a zero-grant authenticated user gets `not_allowed`. Read-only.
	 */
	listPrincipals(input: ListPrincipalsInput): Promise<ListPrincipalsResult>
	/**
	 * Revoke a previously-issued opaque `px_` credential (an API key / share link) by id. The caller
	 * is resolved from the forwarded Access credentials and authorized: the original issuer may always
	 * revoke; otherwise, for an anonymous credential, the caller must hold every granted action (an
	 * admin / app-wide operator). Idempotent — revoking an already-revoked credential returns
	 * `{ ok: true, revoked: false }`. An unknown id returns `{ ok: false, reason: 'not_found' }`.
	 */
	revokeKey(input: RevokeKeyInput): Promise<RevokeKeyResult>
}
