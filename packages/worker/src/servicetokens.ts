import type {
	IssueServiceTokenInput,
	IssueServiceTokenResult,
	PermissionEntry,
	RevokeServiceTokenInput,
	RevokeServiceTokenResult,
	RotateServiceTokenInput,
	RotateServiceTokenResult,
	Scope,
} from '@propustka/core'
import { permits } from '@propustka/core'
import { API_KEY_PREFIX } from '@propustka/core'
import { generateToken, hashToken } from './capabilities'
import { CfAccessError, type MintedServiceToken } from './cfaccess'
import { resolveServicePermissions } from './resolve'
import type { Services } from './services'

/** Mint a propustka-native `px_` credential bound to a service principal; returns the plaintext once. */
async function mintNativeKey(services: Services, principalId: string, issuedBy: string, label: string, expiresAt: number | null): Promise<string> {
	const apiKey = `${API_KEY_PREFIX}${generateToken()}`
	await services.db.createCredential({ tokenHash: await hashToken(apiKey), label, principalId, issuedBy, expiresAt, grants: [] })
	return apiKey
}

/** The resolved caller (issuer / revoker), as `index.ts` resolves it from the forwarded JWT. */
interface Caller {
	id: string
	label: string
	permissions: PermissionEntry[]
}

/**
 * Delegation check (pure): every requested action pattern must be covered by the caller's
 * permissions on `scope`, using the same `permits` matching as `can()`. Returns the first
 * uncovered action, or null when all are covered. Mirrors capabilities' `findUncoveredGrant`.
 */
export function findUncoveredAction(
	callerPermissions: PermissionEntry[],
	permissions: string[],
	scope: Scope | null,
): string | null {
	for (const action of permissions) {
		if (!permits(callerPermissions, action, scope ?? undefined)) {
			return action
		}
	}
	return null
}

// ── Issue ───────────────────────────────────────────────────────────────────────

/**
 * Mint an Access service token + back it with a service principal carrying the requested grant.
 * Enforces the delegation rule first (the issuer must hold every action on `scope`), then mints
 * the token (account API), creates the principal + grant, and returns the secret ONCE. No
 * distributed transaction exists, so a failure after the mint best-effort deletes the orphaned
 * Access token; if THAT also fails an `iam.servicetoken.orphaned` audit row is written so the
 * orphan is never silent. The success audit (`iam.servicetoken.create`) is the entrypoint's job.
 */
export async function issueServiceToken(
	services: Services,
	input: IssueServiceTokenInput,
	issuer: Caller,
	app: string,
): Promise<IssueServiceTokenResult> {
	const scope = input.scope ?? null
	if (findUncoveredAction(issuer.permissions, input.permissions, scope) !== null) {
		return { ok: false, reason: 'not_allowed' }
	}

	const cf = services.cfAccess

	// 1. Mint the Access token. A failure here created nothing — clean.
	let minted: MintedServiceToken
	try {
		minted = await cf.createServiceToken(input.label)
	} catch (err) {
		console.error(`createServiceToken failed for request '${input.requestId}'`, err)
		return { ok: false, reason: 'provisioning_failed' }
	}

	// 2. Create the IAM principal + grant. On failure, roll the Access token back.
	try {
		const principal = await services.db.createService(minted.clientId, input.label)
		await services.db.createGrant({
			principalId: principal.id,
			app,
			permissions: input.permissions,
			scopeType: scope?.type ?? null,
			scopeValue: scope?.value ?? null,
			grantedBy: issuer.id,
			expiresAt: input.expiresAt ?? null,
		})
		// Mint the propustka-native key too (add-only), bound to the same principal.
		const apiKey = await mintNativeKey(services, principal.id, issuer.id, input.label, input.expiresAt ?? null)
		return { ok: true, principalId: principal.id, clientId: minted.clientId, clientSecret: minted.clientSecret, tokenId: minted.id, apiKey }
	} catch (err) {
		console.error(`service principal provisioning failed for request '${input.requestId}'`, err)
		try {
			await cf.deleteServiceToken(minted.id)
		} catch {
			await services.db.writeAuditEvent({
				requestId: input.requestId,
				principalId: issuer.id,
				principalLabel: issuer.label,
				app,
				action: 'iam.servicetoken.orphaned',
				resourceType: 'principal',
				resourceId: null,
				diff: undefined,
				metadata: { tokenId: minted.id, clientId: minted.clientId, label: input.label },
			})
		}
		return { ok: false, reason: 'provisioning_failed' }
	}
}

// ── Revoke / rotate authorization ─────────────────────────────────────────────

/**
 * Authorize a caller to manage an existing service principal: it must be able to (re-)issue the
 * principal's grants — hold every action the principal's resolved permissions confer, on their
 * scope (an admin / app-wide or scope-matching operator). Same rule as capability revoke. Returns
 * the loaded principal on success, or a typed failure reason. Used by revoke + rotate.
 */
async function authorizeManage(
	services: Services,
	principalId: string,
	caller: Caller,
	app: string,
): Promise<
	{ ok: true; principal: { id: string; external_id: string | null; disabled_at: number | null } } | { ok: false; reason: 'not_found' | 'not_allowed' }
> {
	const principal = await services.db.getPrincipalById(principalId)
	if (!principal || principal.type !== 'service') {
		return { ok: false, reason: 'not_found' }
	}
	const principalPerms = await resolveServicePermissions(services.db, principal, app)
	for (const entry of principalPerms) {
		if (!permits(caller.permissions, entry.action, entry.scope ?? undefined)) {
			return { ok: false, reason: 'not_allowed' }
		}
	}
	return { ok: true, principal }
}

// ── Revoke ──────────────────────────────────────────────────────────────────────

/**
 * Revoke a service token: delete the Access token (best-effort — IAM cleanup proceeds even if
 * Access already lost it), hard-delete the principal's grants, and soft-disable the principal.
 * Idempotent — a principal already disabled returns `{ ok: true, revoked: false }`.
 */
export async function revokeServiceToken(
	services: Services,
	input: RevokeServiceTokenInput,
	revoker: Caller,
	app: string,
): Promise<RevokeServiceTokenResult> {
	const authorized = await authorizeManage(services, input.principalId, revoker, app)
	if (!authorized.ok) {
		return authorized
	}
	const { principal } = authorized
	if (principal.disabled_at !== null) {
		return { ok: true, revoked: false }
	}

	if (principal.external_id !== null) {
		const cf = services.cfAccess
		try {
			const tokenId = await cf.findTokenIdByClientId(principal.external_id)
			if (tokenId) {
				await cf.deleteServiceToken(tokenId)
			}
		} catch (err) {
			console.error(`Access token delete failed for principal '${principal.id}'`, err)
		}
	}

	await services.db.deleteGrantsForPrincipal(principal.id)
	await services.db.disablePrincipal(principal.id)
	await services.db.revokeCredentialsForPrincipal(principal.id)
	return { ok: true, revoked: true }
}

// ── Rotate ──────────────────────────────────────────────────────────────────────

/**
 * Rotate a service token's secret — principal id, client_id and grants unchanged. Resolves the
 * Access token id from the stored client_id, rotates via the Access API, returns the new secret
 * ONCE. A CF API failure reports `provisioning_failed`.
 */
export async function rotateServiceToken(
	services: Services,
	input: RotateServiceTokenInput,
	caller: Caller,
	app: string,
): Promise<RotateServiceTokenResult> {
	const authorized = await authorizeManage(services, input.principalId, caller, app)
	if (!authorized.ok) {
		return authorized
	}
	const { principal } = authorized
	if (principal.external_id === null) {
		return { ok: false, reason: 'not_found' }
	}

	const cf = services.cfAccess
	try {
		const tokenId = await cf.findTokenIdByClientId(principal.external_id)
		if (!tokenId) {
			return { ok: false, reason: 'not_found' }
		}
		const rotated = await cf.rotateServiceToken(tokenId)
		// Rotate the native key in lockstep: revoke the old credentials, mint a fresh one.
		await services.db.revokeCredentialsForPrincipal(principal.id)
		const apiKey = await mintNativeKey(services, principal.id, caller.id, principal.external_id, null)
		return { ok: true, clientId: rotated.clientId, clientSecret: rotated.clientSecret, tokenId: rotated.id, apiKey }
	} catch (err) {
		if (!(err instanceof CfAccessError)) {
			throw err
		}
		console.error(`rotateServiceToken failed for principal '${principal.id}'`, err)
		return { ok: false, reason: 'provisioning_failed' }
	}
}
