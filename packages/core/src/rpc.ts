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

export interface AuthenticateInput {
	/** Self-asserted caller app id; superseded by the aud-derived app id on valid tokens. */
	app: string
	/** Cf-Access-Jwt-Assertion header value. */
	token: string | null
	/** CF_Authorization cookie value, for get-identity (users only). */
	cookie: string | null
	/** The app's own origin (for get-identity). */
	origin: string | null
	requestId: string
}

export interface ResolvedPrincipal {
	id: string
	type: PrincipalType
	label: string
	permissions: PermissionEntry[]
	requestId: string
}

export type AuthenticateResult =
	/** get-identity failed → explicit grants only this request (`groupsUnavailable`). */
	| { ok: true; principal: ResolvedPrincipal; groupsUnavailable?: true }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' }

export interface AuditInput {
	app: string
	requestId: string
	/** NULL for capability-driven events. */
	principalId: string | null
	/** Snapshot — survives principal deletion (token label for capabilities). */
	principalLabel: string
	/** Set for capability-driven events. */
	capabilityTokenId?: string
	action: string
	resourceType: string
	resourceId?: string
	diff?: unknown
	metadata?: unknown
}

export interface RedeemCapabilityInput {
	app: string
	token: string
	requestId: string
}

export interface CapabilityGrant {
	action: string
	resource: string
}

export type RedeemCapabilityResult =
	| { ok: true; capabilities: CapabilityGrant[]; tokenId: string; label: string | null }
	| { ok: false; reason: 'unknown' | 'expired' | 'revoked' | 'exhausted' }

export interface IssueCapabilityGrant {
	action: string
	resource: string
	/** Scope for the delegation check ONLY (not stored). Omitted → issuer must hold the action globally. */
	scope?: Scope | null
}

export interface IssueCapabilityInput {
	app: string
	/** The ISSUER's Access JWT — issuer is resolved server-side, never self-asserted. */
	token: string | null
	/** Issuer's CF_Authorization cookie (group-derived permissions count toward delegation too). */
	cookie: string | null
	origin: string | null
	requestId: string
	grants: IssueCapabilityGrant[]
	label?: string
	expiresAt?: number
	maxUses?: number
}

export type IssueCapabilityResult =
	/** Plaintext token returned ONCE. */
	| { ok: true; token: string; id: string }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' }

export interface RevokeCapabilityInput {
	app: string
	/** The CALLER's Access JWT — the authorizer is resolved server-side, never self-asserted. */
	token: string | null
	/** Caller's CF_Authorization cookie (group-derived permissions count toward the revoke check). */
	cookie: string | null
	origin: string | null
	requestId: string
	/** The capability token id (the `id` returned by issueCapability), NOT the plaintext token. */
	tokenId: string
}

export type RevokeCapabilityResult =
	/** `revoked` is false when the token was already revoked (idempotent). */
	| { ok: true; revoked: boolean }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found' }

// ── Service tokens (machine principals) ────────────────────────────────────────
//
// A service token is a Cloudflare Access service token (client_id + client_secret) backed
// by a propustka SERVICE principal carrying real grants — so a machine caller is authorized
// through `can()`/`scopedTo()` exactly like a user, not as an anonymous capability. Issuing
// one mints the Access token (account API) AND creates the principal + grant, so it is a
// privileged op exposed over the binding as a DELEGATED call: the issuer is resolved from the
// forwarded Access JWT and may only grant what it itself holds (the same delegation rule as
// `issueCapability`). The plaintext `clientSecret` is returned ONCE. The minted token works at
// the edge only on an Access app whose Service Auth policy accepts it (e.g. "Any Access Service
// Token"); per-resource authorization is the propustka grant, never the edge.

export interface IssueServiceTokenInput {
	app: string
	/** The ISSUER's Access JWT — issuer is resolved server-side, never self-asserted. */
	token: string | null
	/** Issuer's CF_Authorization cookie (group-derived permissions count toward delegation too). */
	cookie: string | null
	origin: string | null
	requestId: string
	/** Display name in Access + the IAM principal label. */
	label: string
	/**
	 * Inline action patterns granted to the new service principal (the binding path is
	 * inline-only; named roles stay an admin-HTTP concern). Each is delegation-checked against
	 * the issuer on `scope` — the issuer must itself hold every action there.
	 */
	permissions: string[]
	/** Scope the grant + the delegation check apply to; omitted/null → global. */
	scope?: Scope | null
	/** Optional grant expiry (unix seconds). */
	expiresAt?: number
}

export type IssueServiceTokenResult =
	/** Plaintext `clientSecret` returned ONCE; `principalId` is the stable IAM handle for revoke/rotate. */
	| { ok: true; principalId: string; clientId: string; clientSecret: string; tokenId: string }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'provisioning_failed' }

export interface RevokeServiceTokenInput {
	app: string
	/** The CALLER's Access JWT — the authorizer is resolved server-side, never self-asserted. */
	token: string | null
	cookie: string | null
	origin: string | null
	requestId: string
	/** The service PRINCIPAL id (the `principalId` from issueServiceToken), NOT the client_id. */
	principalId: string
}

export type RevokeServiceTokenResult =
	/** `revoked` is false when the principal was already disabled (idempotent). */
	| { ok: true; revoked: boolean }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found' }

export interface RotateServiceTokenInput {
	app: string
	token: string | null
	cookie: string | null
	origin: string | null
	requestId: string
	/** The service PRINCIPAL id whose secret to rotate; the principal + its grants are unchanged. */
	principalId: string
}

export type RotateServiceTokenResult =
	/** New plaintext `clientSecret` returned ONCE; the client_id is unchanged. */
	| { ok: true; clientId: string; clientSecret: string; tokenId: string }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found' | 'provisioning_failed' }

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
	/** Self-asserted caller app id; superseded by the aud-derived app id on the valid token. */
	app: string
	/** Cf-Access-Jwt-Assertion header value. */
	token: string | null
	/** CF_Authorization cookie value, for get-identity. */
	cookie: string | null
	/** The app's own origin (for get-identity). */
	origin: string | null
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
	authenticate(input: AuthenticateInput): Promise<AuthenticateResult>
	/**
	 * Mint a short-lived, per-app permission token from the browser's SSO session — the
	 * propustka-native auth path. The SDK middleware calls this only when its cached permission
	 * token is missing/near-expiry (≈ once per TTL), NOT per request: every other request verifies
	 * the cached token locally against `getJwks`.
	 */
	mintToken(input: MintTokenInput): Promise<MintTokenResult>
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
	redeemCapability(input: RedeemCapabilityInput): Promise<RedeemCapabilityResult>
	issueCapability(input: IssueCapabilityInput): Promise<IssueCapabilityResult>
	/**
	 * Revoke a previously-issued capability token by id. The caller is resolved from the
	 * forwarded Access credentials and authorized: the original issuer may always revoke;
	 * otherwise the caller must hold every granted action globally (an admin / app-wide
	 * operator). Idempotent — revoking an already-revoked token returns `{ ok: true,
	 * revoked: false }`. An unknown id returns `{ ok: false, reason: 'not_found' }`.
	 */
	revokeCapability(input: RevokeCapabilityInput): Promise<RevokeCapabilityResult>
	/**
	 * Mint a Cloudflare Access service token and back it with a SERVICE principal carrying the
	 * requested grant. Delegated like `issueCapability`: the issuer is resolved from the forwarded
	 * Access JWT and may only grant actions it itself holds on `scope` (else `not_allowed`). The
	 * Access token is minted via the account API, the principal + grant created, and the plaintext
	 * `clientSecret` returned ONCE; a CF API failure reports `provisioning_failed` and rolls the
	 * Access token back. `principalId` is the durable handle for revoke/rotate.
	 */
	issueServiceToken(input: IssueServiceTokenInput): Promise<IssueServiceTokenResult>
	/**
	 * Revoke a service token by its principal id: delete the Access token, drop the principal's
	 * grants, and disable the principal. The caller is resolved from the forwarded credentials and
	 * authorized like a capability revoke — it must be able to (re-)issue the principal's grants
	 * (hold every granted action on its scope). Idempotent; an unknown principal → `not_found`.
	 */
	revokeServiceToken(input: RevokeServiceTokenInput): Promise<RevokeServiceTokenResult>
	/**
	 * Rotate a service token's secret (principal id, client_id and grants unchanged), returning the
	 * new `clientSecret` ONCE. Same caller authorization as `revokeServiceToken`.
	 */
	rotateServiceToken(input: RotateServiceTokenInput): Promise<RotateServiceTokenResult>
}
