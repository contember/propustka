import type { DomainEvent, IamRpc, ResolvedPrincipal, Scope } from '@propustka/core'
import { permits, scopedValues } from '@propustka/core'
import { readCredentials } from './request'
import type {
	AuthContext,
	AuthFailure,
	Capability,
	CapabilityFailure,
	IssueCapabilityRequest,
	IssuedCapability,
	IssueFailure,
	PrincipalIdentity,
	RevokedCapability,
	RevokeFailure,
} from './types'

// ── AuthContext (real) ─────────────────────────────────────────────────────────

/**
 * The real, principal-backed `AuthContext`. `can`/`scopedTo` are pure functions over the
 * permissions array the IAM Worker already resolved (no per-check round-trip); only `audit`
 * calls the binding.
 */
class RealAuthContext implements AuthContext {
	readonly ok = true
	readonly principal: PrincipalIdentity

	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
		private readonly resolved: ResolvedPrincipal,
	) {
		this.principal = { id: resolved.id, type: resolved.type, label: resolved.label }
	}

	can(action: string, scope?: Scope): boolean {
		// `permits` already encodes the scope-less rule: with no scope, ONLY global
		// (scope === null) entries satisfy.
		return permits(this.resolved.permissions, action, scope)
	}

	scopedTo(action: string, dimension: string): string[] | null {
		// `dimension` picks the scope type — scopes are flat & independent, so a value
		// list is always relative to one dimension.
		return scopedValues(this.resolved.permissions, action, dimension)
	}

	audit(event: DomainEvent): Promise<void> {
		return this.binding.audit({
			app: this.appId,
			requestId: this.resolved.requestId,
			principalId: this.resolved.id,
			principalLabel: this.resolved.label,
			action: event.action,
			resourceType: event.resourceType,
			resourceId: event.resourceId,
			diff: event.diff,
			metadata: event.metadata,
		})
	}
}

// ── Capability (real) ──────────────────────────────────────────────────────────

/**
 * A redeemed, anonymous capability token. `can` is EXACT-match (action, resource) — no
 * wildcards. `audit` attaches the token id + label and a null principal.
 */
class RealCapability implements Capability {
	readonly ok = true

	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
		private readonly requestId: string,
		private readonly tokenId: string,
		private readonly label: string | null,
		private readonly capabilities: ReadonlyArray<{ action: string; resource: string }>,
	) {}

	can(action: string, resource: string): boolean {
		for (const c of this.capabilities) {
			if (c.action === action && c.resource === resource) {
				return true
			}
		}
		return false
	}

	audit(event: DomainEvent): Promise<void> {
		return this.binding.audit({
			app: this.appId,
			requestId: this.requestId,
			principalId: null,
			// Snapshot the token label; fall back to `capability:<id>` when unlabeled.
			principalLabel: this.label ?? `capability:${this.tokenId}`,
			capabilityTokenId: this.tokenId,
			action: event.action,
			resourceType: event.resourceType,
			resourceId: event.resourceId,
			diff: event.diff,
			metadata: event.metadata,
		})
	}
}

// ── IamClient ──────────────────────────────────────────────────────────────────

/**
 * Thin, app-facing wrapper over the IAM Worker service binding. Bakes the caller `app` id
 * into the constructor so app code can never forget or mistype it. Depends ONLY on the
 * `IamRpc` contract from `@propustka/core` — never on the Worker — which is what keeps the
 * SDK worker-independent (the binding is the deployed Worker, reached at runtime).
 */
export class IamClient {
	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
	) {}

	/**
	 * Resolve the caller from the forwarded Access credentials. Returns a rich `AuthContext`
	 * on success, or a typed `AuthFailure` carrying the 401/403 status (missing/invalid → 401;
	 * unknown_principal/disabled → 403).
	 */
	async authenticate(req: Request): Promise<AuthContext | AuthFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.authenticate({ app: this.appId, token, cookie, origin, requestId })
		if (result.ok) {
			return new RealAuthContext(this.binding, this.appId, result.principal)
		}
		return { ok: false, reason: result.reason, status: authFailureStatus(result.reason) }
	}

	/**
	 * Redeem a capability token (a share link). No identity. A bad/expired/revoked/exhausted
	 * token reads as a 404 (the link is "invalid or expired"), never a leaky 401/403.
	 */
	async redeemCapability(req: Request, token: string): Promise<Capability | CapabilityFailure> {
		const { requestId } = readCredentials(req)
		const result = await this.binding.redeemCapability({ app: this.appId, token, requestId })
		if (result.ok) {
			return new RealCapability(this.binding, this.appId, requestId, result.tokenId, result.label, result.capabilities)
		}
		return { ok: false, reason: result.reason, status: 404 }
	}

	/**
	 * Mint a capability (share link) in-flow. Forwards the REQUESTER's credentials as the
	 * issuer — the IAM Worker resolves the issuer server-side and enforces the delegation rule
	 * (you can only delegate what you can do). The app supplies only the grants/label/expiry.
	 */
	async issueCapability(req: Request, input: IssueCapabilityRequest): Promise<IssuedCapability | IssueFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.issueCapability({
			app: this.appId,
			token,
			cookie,
			origin,
			requestId,
			grants: input.grants,
			label: input.label,
			expiresAt: input.expiresAt,
			maxUses: input.maxUses,
		})
		if (result.ok) {
			return { ok: true, token: result.token, id: result.id }
		}
		return { ok: false, reason: result.reason, status: issueFailureStatus(result.reason) }
	}

	/**
	 * Revoke a capability (share link) by its id. Forwards the CALLER's credentials as the
	 * authorizer — the IAM Worker resolves the caller server-side and enforces the rule (the
	 * original issuer, or anyone who could re-issue the grants, may revoke). Idempotent: a
	 * second revoke returns `{ ok: true, revoked: false }`. An unknown id → 404.
	 */
	async revokeCapability(req: Request, tokenId: string): Promise<RevokedCapability | RevokeFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.revokeCapability({ app: this.appId, token, cookie, origin, requestId, tokenId })
		if (result.ok) {
			return { ok: true, revoked: result.revoked }
		}
		return { ok: false, reason: result.reason, status: revokeFailureStatus(result.reason) }
	}
}

/** missing/invalid token → 401 (not authenticated); unknown/disabled principal → 403. */
function authFailureStatus(reason: AuthFailure['reason']): 401 | 403 {
	return reason === 'missing_token' || reason === 'invalid_token' ? 401 : 403
}

/** missing/invalid → 401; unknown_principal/disabled/not_allowed → 403. */
function issueFailureStatus(reason: IssueFailure['reason']): 401 | 403 {
	return reason === 'missing_token' || reason === 'invalid_token' ? 401 : 403
}

/** missing/invalid → 401; not_found → 404; unknown_principal/disabled/not_allowed → 403. */
function revokeFailureStatus(reason: RevokeFailure['reason']): 401 | 403 | 404 {
	if (reason === 'missing_token' || reason === 'invalid_token') return 401
	if (reason === 'not_found') return 404
	return 403
}
