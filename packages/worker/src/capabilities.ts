import type {
	IssueCapabilityGrant,
	IssueCapabilityInput,
	IssueCapabilityResult,
	PermissionEntry,
	RedeemCapabilityInput,
	RedeemCapabilityResult,
	RevokeCapabilityInput,
	RevokeCapabilityResult,
} from '@propustka/core'
import { permits, uuidv7 } from '@propustka/core'
import type { CapabilityTokenRow } from './db'
import type { Services } from './services'

// ── Token hashing & generation ────────────────────────────────────────────────

/** SHA-256 hex of a token. Only the hash is stored — a DB leak yields no usable token. */
export async function hashToken(token: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

/**
 * Generate a high-entropy random token (160 bits, > the 128-bit minimum) as
 * URL-safe base64url. The plaintext is shown once at issue and never stored.
 */
export function generateToken(): string {
	const bytes = new Uint8Array(20)
	crypto.getRandomValues(bytes)
	let binary = ''
	for (const b of bytes) {
		binary += String.fromCharCode(b)
	}
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

// ── Redeem failure classification (pure) ──────────────────────────────────────

export type RedeemFailureReason = 'unknown' | 'expired' | 'revoked' | 'exhausted'

/**
 * Classify why a redeem matched zero rows, given the token row found by hash (or
 * null). Pure — separated from D1 so it is unit-testable. Order matters: a token
 * can be both expired and revoked; we report the most actionable cause. `now` is
 * unix seconds.
 */
export function classifyRedeemFailure(row: CapabilityTokenRow | null, now: number): RedeemFailureReason {
	if (!row) {
		return 'unknown'
	}
	if (row.revoked_at !== null) {
		return 'revoked'
	}
	if (row.expires_at !== null && row.expires_at <= now) {
		return 'expired'
	}
	if (row.max_uses !== null && row.used_count >= row.max_uses) {
		return 'exhausted'
	}
	// Hash matched but none of the above — should not normally happen (the atomic
	// UPDATE would have succeeded). Treat as unknown to fail closed.
	return 'unknown'
}

// ── Redeem ────────────────────────────────────────────────────────────────────

export async function redeemCapability(services: Services, input: RedeemCapabilityInput): Promise<RedeemCapabilityResult> {
	const tokenHash = await hashToken(input.token)
	const redeemed = await services.db.redeemCapabilityToken(tokenHash)
	if (!redeemed) {
		const row = await services.db.getCapabilityTokenByHash(tokenHash)
		const reason = classifyRedeemFailure(row, Math.floor(Date.now() / 1000))
		return { ok: false, reason }
	}

	const grants = await services.db.getCapabilityGrants(redeemed.id)
	return {
		ok: true,
		capabilities: grants.map((g) => ({ action: g.action, resource: g.resource })),
		tokenId: redeemed.id,
		label: redeemed.label,
	}
}

// ── Issue (delegation rule) ───────────────────────────────────────────────────

/**
 * Delegation check (pure): every requested grant's action must be covered by the
 * issuer's permissions, using the same matching as `can()` — scoped to the grant's
 * `projectId` when given (omitted → the issuer must hold the action globally).
 * Returns the first uncovered grant, or null if all are covered.
 */
export function findUncoveredGrant(
	issuerPermissions: PermissionEntry[],
	grants: IssueCapabilityGrant[],
): IssueCapabilityGrant | null {
	for (const grant of grants) {
		const scope = grant.projectId ?? undefined
		if (!permits(issuerPermissions, grant.action, scope)) {
			return grant
		}
	}
	return null
}

export async function issueCapability(
	services: Services,
	input: IssueCapabilityInput,
	issuer: { id: string; permissions: PermissionEntry[] },
): Promise<{ result: IssueCapabilityResult; auditLabel?: string }> {
	// Enforce the delegation rule: you can only delegate what you can do.
	const uncovered = findUncoveredGrant(issuer.permissions, input.grants)
	if (uncovered) {
		return { result: { ok: false, reason: 'not_allowed' } }
	}

	const token = generateToken()
	const tokenHash = await hashToken(token)
	const id = await services.db.createCapabilityToken({
		tokenHash,
		label: input.label ?? null,
		issuedBy: issuer.id,
		expiresAt: input.expiresAt ?? null,
		maxUses: input.maxUses ?? null,
		// Store only (action, resource) — projectId was for the delegation check only.
		grants: input.grants.map((g) => ({ action: g.action, resource: g.resource })),
	})

	return { result: { ok: true, token, id }, auditLabel: input.label }
}

// ── Revoke (authorization rule) ───────────────────────────────────────────────

/**
 * Revoke a capability token by id. Authorization (pure-ish, one DB read for grants):
 * the original issuer may always revoke; otherwise the caller must be able to (re-)issue
 * the token's grants — i.e. hold every granted action GLOBALLY (an admin / app-wide
 * operator), checked with the same `findUncoveredGrant` as issue. A project-scoped
 * operator can therefore revoke only what it issued: the grant's `projectId` is not
 * stored (it was a delegation-check input at issue time), so scoped re-delegation can't
 * be re-derived here — we fail closed to issuer-or-global rather than guess. Idempotent.
 */
export async function revokeCapability(
	services: Services,
	input: RevokeCapabilityInput,
	revoker: { id: string; permissions: PermissionEntry[] },
): Promise<RevokeCapabilityResult> {
	const row = await services.db.getCapabilityTokenById(input.tokenId)
	if (!row) {
		return { ok: false, reason: 'not_found' }
	}
	if (row.issued_by !== revoker.id) {
		const grants = await services.db.getCapabilityGrants(input.tokenId)
		const uncovered = findUncoveredGrant(
			revoker.permissions,
			grants.map((g) => ({ action: g.action, resource: g.resource })),
		)
		if (uncovered) {
			return { ok: false, reason: 'not_allowed' }
		}
	}
	const revoked = await services.db.revokeCapabilityToken(input.tokenId)
	return { ok: true, revoked }
}

/** A fresh capability token id is a UUIDv7 (exposed for callers that pre-generate). */
export const newCapabilityId = uuidv7
