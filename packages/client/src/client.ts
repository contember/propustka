import type { DomainEvent, IamRpc, ResolvedPrincipal } from '@propustka/core'
import { matchAction, permits } from '@propustka/core'
import { readCredentials } from './request'
import type { AuthContext, AuthFailure, Capability, CapabilityFailure, IssueCapabilityRequest, IssuedCapability, IssueFailure } from './types'

// ── AuthContext (real) ─────────────────────────────────────────────────────────

/**
 * The real, principal-backed `AuthContext`. `can`/`scopedTo` are pure functions over the
 * permissions array the IAM Worker already resolved (no per-check round-trip); only `audit`
 * calls the binding.
 */
class RealAuthContext implements AuthContext {
	readonly ok = true

	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
		private readonly principal: ResolvedPrincipal,
	) {}

	can(action: string, scope?: { project?: string }): boolean {
		// `permits` already encodes the scope-less rule: with no project, ONLY global
		// (projectId === null) entries satisfy.
		return permits(this.principal.permissions, action, scope?.project)
	}

	scopedTo(action: string, _dimension = 'project'): string[] | null {
		// `dimension` is forward-looking only — v1 has a single scope dimension (project).
		const ids: string[] = []
		const seen = new Set<string>()
		for (const entry of this.principal.permissions) {
			if (!matchAction(entry.action, action)) {
				continue
			}
			// A matching global entry means unrestricted — short-circuit to null.
			if (entry.projectId === null) {
				return null
			}
			if (!seen.has(entry.projectId)) {
				seen.add(entry.projectId)
				ids.push(entry.projectId)
			}
		}
		return ids
	}

	audit(event: DomainEvent): Promise<void> {
		return this.binding.audit({
			app: this.appId,
			requestId: this.principal.requestId,
			principalId: this.principal.id,
			principalLabel: this.principal.label,
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
}

/** missing/invalid token → 401 (not authenticated); unknown/disabled principal → 403. */
function authFailureStatus(reason: AuthFailure['reason']): 401 | 403 {
	return reason === 'missing_token' || reason === 'invalid_token' ? 401 : 403
}

/** missing/invalid → 401; unknown_principal/disabled/not_allowed → 403. */
function issueFailureStatus(reason: IssueFailure['reason']): 401 | 403 {
	return reason === 'missing_token' || reason === 'invalid_token' ? 401 : 403
}
