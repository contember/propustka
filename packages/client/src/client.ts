import type { AccessTokenClaims, DomainEvent, IamRpc, PermissionEntry, Scope } from '@propustka/core'
import { permits, scopedValues } from '@propustka/core'
import { readCredentials } from './request'
import type {
	AuthContext,
	AuthFailure,
	IssuedJwt,
	IssuedKey,
	IssuedServiceToken,
	IssueFailure,
	IssueJwtRequest,
	IssueKeyRequest,
	IssueServiceTokenFailure,
	IssueServiceTokenRequest,
	ListPrincipalsFailure,
	PrincipalIdentity,
	PrincipalList,
	RevokedKey,
	RevokedServiceToken,
	RevokeFailure,
	RevokeServiceTokenFailure,
	RotatedServiceToken,
	RotateServiceTokenFailure,
} from './types'

// ── AuthContext (real) ─────────────────────────────────────────────────────────

/**
 * The real `AuthContext`. `can`/`scopedTo` are pure functions over the resolved permission array (no
 * per-check round-trip); only `audit` calls the binding. Backs BOTH a principal-bound caller (cookie
 * session / API key) and an ANONYMOUS one (passthrough JWT / standalone share link) — the latter has
 * `principal = null`; `audit` then attributes to the credential label + token id, principal null.
 */
class RealAuthContext implements AuthContext {
	readonly ok = true

	constructor(
		private readonly binding: IamRpc,
		private readonly appId: string,
		private readonly permissions: PermissionEntry[],
		private readonly requestId: string,
		readonly principal: PrincipalIdentity | null,
		/** Audit actor label — the principal's label, or the credential/jwt label. */
		private readonly auditLabel: string,
		/** The credential/token id, for the audit linkage of an anonymous caller (null when bound). */
		private readonly anonymousTokenId: string | null,
	) {}

	can(action: string, scope?: Scope): boolean {
		// `permits` already encodes the scope-less rule: with no scope, ONLY global
		// (scope === null) entries satisfy.
		return permits(this.permissions, action, scope)
	}

	scopedTo(action: string, dimension: string): string[] | null {
		// `dimension` picks the scope type — scopes are flat & independent, so a value
		// list is always relative to one dimension.
		return scopedValues(this.permissions, action, dimension)
	}

	audit(event: DomainEvent): Promise<void> {
		return this.binding.audit({
			app: this.appId,
			requestId: this.requestId,
			principalId: this.principal?.id ?? null,
			principalLabel: this.auditLabel,
			...(this.anonymousTokenId === null ? {} : { credentialId: this.anonymousTokenId }),
			action: event.action,
			resourceType: event.resourceType,
			resourceId: event.resourceId,
			diff: event.diff,
			metadata: event.metadata,
		})
	}
}

/**
 * Build an `AuthContext` from a verified access token's claims — the seam every propustka-native auth
 * path uses (cookie session, API-key bearer, passthrough JWT). The SDK has verified the token LOCALLY;
 * this wraps its claims in the same `permits`-backed context the RPC path returns, so `can()` /
 * `scopedTo()` / `audit()` behave identically. A token with no `ptype` is anonymous (`principal: null`).
 */
export function buildAuthContext(binding: IamRpc, appId: string, claims: AccessTokenClaims, requestId: string): AuthContext {
	const principal: PrincipalIdentity | null = claims.ptype === undefined
		? null
		: { id: claims.sub, type: claims.ptype, label: claims.label ?? claims.sub }
	const auditLabel = claims.label ?? (principal === null ? `credential:${claims.sub}` : claims.sub)
	return new RealAuthContext(binding, appId, claims.perms, requestId, principal, auditLabel, principal === null ? claims.sub : null)
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
			const p = result.principal
			return new RealAuthContext(this.binding, this.appId, p.permissions, p.requestId, { id: p.id, type: p.type, label: p.label }, p.label, null)
		}
		return { ok: false, reason: result.reason, status: authFailureStatus(result.reason) }
	}

	/**
	 * List the app's people directory — the USER principals who can access this app. Forwards the
	 * CALLER's credentials; the IAM Worker resolves the caller and scopes the roster to the
	 * aud-verified app (you only ever see your own app's people). For an assignee picker / actor
	 * label list. Authorized for any member with a permission on the app; a zero-grant user → 403.
	 */
	async listPrincipals(req: Request): Promise<PrincipalList | ListPrincipalsFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.listPrincipals({ app: this.appId, token, cookie, origin, requestId })
		if (result.ok) {
			return { ok: true, principals: result.principals }
		}
		return { ok: false, reason: result.reason, status: listPrincipalsStatus(result.reason) }
	}

	/**
	 * Mint an opaque, stored, revocable `px_` credential (API key / share link). Forwards the
	 * REQUESTER's credentials as the issuer — the IAM Worker resolves the issuer server-side and
	 * enforces the delegation rule (you can only delegate what you can do). Returns the plaintext
	 * `px_` token ONCE; persist only the `id` (the handle for `revokeKey`). The transport — bearer
	 * header for a machine, URL-path token for a share link — is the app's choice.
	 */
	async issueKey(req: Request, input: IssueKeyRequest): Promise<IssuedKey | IssueFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.issueKey({
			app: this.appId,
			token,
			cookie,
			origin,
			requestId,
			principalId: input.principalId,
			permissions: input.permissions,
			label: input.label,
			expiresAt: input.expiresAt,
		})
		if (result.ok) {
			return { ok: true, token: result.token, id: result.id }
		}
		return { ok: false, reason: result.reason, status: issueFailureStatus(result.reason) }
	}

	/**
	 * Sign a stateless passthrough access token (audit-only, TTL-bounded, NOT revocable). Forwards the
	 * REQUESTER's credentials as the issuer (same delegation rule as `issueKey`). The holder carries the
	 * returned JWT directly as `Authorization: Bearer`; apps verify it locally with no propustka
	 * round-trip. There is nothing to revoke — it is TTL-only by design.
	 */
	async issueJwt(req: Request, input: IssueJwtRequest): Promise<IssuedJwt | IssueFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.issueJwt({
			app: this.appId,
			token,
			cookie,
			origin,
			requestId,
			permissions: input.permissions,
			label: input.label,
			ttl: input.ttl,
		})
		if (result.ok) {
			return { ok: true, token: result.token, expiresAt: result.expiresAt, id: result.id }
		}
		return { ok: false, reason: result.reason, status: issueFailureStatus(result.reason) }
	}

	/**
	 * Revoke an opaque `px_` credential (API key / share link) by its id. Forwards the CALLER's
	 * credentials as the authorizer — the IAM Worker resolves the caller server-side and enforces the
	 * rule (the original issuer, or anyone who could re-issue the grants, may revoke). Idempotent: a
	 * second revoke returns `{ ok: true, revoked: false }`. An unknown id → 404.
	 */
	async revokeKey(req: Request, id: string): Promise<RevokedKey | RevokeFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.revokeKey({ app: this.appId, token, cookie, origin, requestId, id })
		if (result.ok) {
			return { ok: true, revoked: result.revoked }
		}
		return { ok: false, reason: result.reason, status: revokeFailureStatus(result.reason) }
	}

	/**
	 * Mint a service token (machine principal) in-flow. Forwards the REQUESTER's credentials as the
	 * issuer — the IAM Worker resolves the issuer server-side and enforces the delegation rule (you
	 * can only grant what you can do on `scope`). Returns the `clientSecret` ONCE; persist only the
	 * `clientId`/`principalId`. The minted token authenticates at the edge only on an Access app
	 * whose Service Auth policy accepts it; per-resource authorization is the propustka grant.
	 */
	async issueServiceToken(req: Request, input: IssueServiceTokenRequest): Promise<IssuedServiceToken | IssueServiceTokenFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.issueServiceToken({
			app: this.appId,
			token,
			cookie,
			origin,
			requestId,
			label: input.label,
			permissions: input.permissions,
			scope: input.scope,
			expiresAt: input.expiresAt,
		})
		if (result.ok) {
			return {
				ok: true,
				clientId: result.clientId,
				clientSecret: result.clientSecret,
				apiKey: result.apiKey,
				principalId: result.principalId,
				tokenId: result.tokenId,
			}
		}
		return { ok: false, reason: result.reason, status: issueServiceTokenStatus(result.reason) }
	}

	/**
	 * Revoke a service token by its principal id. Forwards the CALLER's credentials as the authorizer
	 * — the IAM Worker resolves the caller server-side and enforces the rule (must be able to re-issue
	 * the principal's grants). Deletes the Access token, drops grants, disables the principal.
	 * Idempotent; an unknown principal → 404.
	 */
	async revokeServiceToken(req: Request, principalId: string): Promise<RevokedServiceToken | RevokeServiceTokenFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.revokeServiceToken({ app: this.appId, token, cookie, origin, requestId, principalId })
		if (result.ok) {
			return { ok: true, revoked: result.revoked }
		}
		return { ok: false, reason: result.reason, status: revokeServiceTokenStatus(result.reason) }
	}

	/**
	 * Rotate a service token's secret (principal id, client_id and grants unchanged). Returns the new
	 * `clientSecret` ONCE. Same caller authorization as `revokeServiceToken`.
	 */
	async rotateServiceToken(req: Request, principalId: string): Promise<RotatedServiceToken | RotateServiceTokenFailure> {
		const { token, cookie, origin, requestId } = readCredentials(req)
		const result = await this.binding.rotateServiceToken({ app: this.appId, token, cookie, origin, requestId, principalId })
		if (result.ok) {
			return { ok: true, clientId: result.clientId, clientSecret: result.clientSecret, apiKey: result.apiKey, tokenId: result.tokenId }
		}
		return { ok: false, reason: result.reason, status: rotateServiceTokenStatus(result.reason) }
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

/** missing/invalid → 401; unknown_principal/disabled/not_allowed → 403. */
function listPrincipalsStatus(reason: ListPrincipalsFailure['reason']): 401 | 403 {
	return reason === 'missing_token' || reason === 'invalid_token' ? 401 : 403
}

/** missing/invalid → 401; not_found → 404; unknown_principal/disabled/not_allowed → 403. */
function revokeFailureStatus(reason: RevokeFailure['reason']): 401 | 403 | 404 {
	if (reason === 'missing_token' || reason === 'invalid_token') return 401
	if (reason === 'not_found') return 404
	return 403
}

/** missing/invalid → 401; provisioning_failed → 502 (CF API); rest → 403. */
function issueServiceTokenStatus(reason: IssueServiceTokenFailure['reason']): 401 | 403 | 502 {
	if (reason === 'missing_token' || reason === 'invalid_token') return 401
	if (reason === 'provisioning_failed') return 502
	return 403
}

/** missing/invalid → 401; not_found → 404; rest → 403. */
function revokeServiceTokenStatus(reason: RevokeServiceTokenFailure['reason']): 401 | 403 | 404 {
	if (reason === 'missing_token' || reason === 'invalid_token') return 401
	if (reason === 'not_found') return 404
	return 403
}

/** missing/invalid → 401; not_found → 404; provisioning_failed → 502; rest → 403. */
function rotateServiceTokenStatus(reason: RotateServiceTokenFailure['reason']): 401 | 403 | 404 | 502 {
	if (reason === 'missing_token' || reason === 'invalid_token') return 401
	if (reason === 'not_found') return 404
	if (reason === 'provisioning_failed') return 502
	return 403
}
