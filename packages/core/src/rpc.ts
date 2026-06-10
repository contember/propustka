import type { PermissionEntry, PrincipalType } from './types'

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
	projectId?: string | null
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

/**
 * The RPC contract. The Worker's `WorkerEntrypoint` `implements IamRpc`; the SDK types its
 * binding as `Service<IamRpc>` (so the SDK never imports the Worker). Methods return plain
 * serializable objects (RPC-friendly).
 */
export interface IamRpc {
	authenticate(input: AuthenticateInput): Promise<AuthenticateResult>
	audit(event: AuditInput): Promise<void>
	redeemCapability(input: RedeemCapabilityInput): Promise<RedeemCapabilityResult>
	issueCapability(input: IssueCapabilityInput): Promise<IssueCapabilityResult>
}
