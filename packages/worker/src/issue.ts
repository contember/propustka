/**
 * Issuing credentials. Two outputs, one delegation rule (see `propustka-native-spec.md`):
 *   - `issueKey` — an opaque, stored, revocable `px_` credential (API key / share link). The token's
 *     EFFECTIVE permissions are resolved at use time (`mintFromKey`); this just persists the row.
 *   - `issueJwt` — a stateless passthrough access token, signed here and returned. Audit-only, not
 *     revocable, TTL-bounded.
 *
 * Both are DELEGATED: the issuer (resolved server-side from the forwarded credentials, never
 * self-asserted) may only grant what it itself holds — the same `permits` rule `can()` uses. The
 * Worker entrypoint resolves the issuer and writes the audit row; this module is the pure-ish core.
 */

import {
	API_KEY_PREFIX,
	DEFAULT_TOKEN_TTL_SECONDS,
	type IssueJwtInput,
	type IssueJwtResult,
	type IssueKeyInput,
	type IssueKeyResult,
	type KeyGrant,
	MAX_PASSTHROUGH_TTL_SECONDS,
	type PermissionEntry,
	permits,
	type RevokeKeyInput,
	type RevokeKeyResult,
	uuidv7,
} from '@propustka/core'
import type { CredentialGrantRow } from './db'
import type { Env } from './env'
import { generateToken, hashToken } from './secret'
import type { Services } from './services'
import { signAccessToken } from './tokens'

/** The resolved caller (issuer), as `index.ts` resolves it from the forwarded JWT. */
interface Issuer {
	id: string
	permissions: PermissionEntry[]
}

type MintEnv = Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>

/**
 * Delegation check (pure): every requested grant must be covered by the issuer's permissions on its
 * scope, using the same `permits` matching as `can()`. Returns the first uncovered grant, or null.
 */
export function findUncoveredGrant(issuerPermissions: PermissionEntry[], grants: KeyGrant[]): KeyGrant | null {
	for (const grant of grants) {
		if (!permits(issuerPermissions, grant.action, grant.scope ?? undefined)) {
			return grant
		}
	}
	return null
}

/** A requested grant → a `PermissionEntry` (source 'grant'). */
function grantToEntry(grant: KeyGrant): PermissionEntry {
	return { action: grant.action, scope: grant.scope ?? null, source: 'grant' }
}

// ── issueKey ──────────────────────────────────────────────────────────────────

export async function issueKey(
	services: Services,
	input: IssueKeyInput,
	issuer: Issuer,
	app: string,
): Promise<{ result: IssueKeyResult; auditLabel?: string }> {
	// Service mode: create a NEW machine principal + grant and bind the key to it (the folded
	// issueServiceToken). The grant is scoped to the issuer's verified `app`; the issuer must hold
	// every requested action on `scope` (the same delegation rule as a grant).
	if (input.service !== undefined) {
		const svc = input.service
		const grants = svc.permissions.map((action) => ({ action, scope: svc.scope ?? null }))
		if (grants.length === 0 || findUncoveredGrant(issuer.permissions, grants) !== null) {
			return { result: { ok: false, reason: 'not_allowed' } }
		}
		const principal = await services.db.createService(svc.label)
		await services.db.createGrant({
			principalId: principal.id,
			app,
			permissions: svc.permissions,
			scopeType: svc.scope?.type ?? null,
			scopeValue: svc.scope?.value ?? null,
			grantedBy: issuer.id,
			expiresAt: input.expiresAt ?? null,
		})
		const token = `${API_KEY_PREFIX}${generateToken()}`
		const id = await services.db.createCredential({
			tokenHash: await hashToken(token),
			label: svc.label,
			principalId: principal.id,
			issuedBy: issuer.id,
			expiresAt: input.expiresAt ?? null,
			grants: [],
		})
		return { result: { ok: true, token, id, principalId: principal.id }, auditLabel: svc.label }
	}

	// v1: binding is only to the issuer's OWN principal (a personal token). A standalone credential
	// needs grants.
	if (input.principalId !== undefined && input.principalId !== issuer.id) {
		return { result: { ok: false, reason: 'not_allowed' } }
	}
	const grants = input.permissions ?? []
	if (input.principalId === undefined && grants.length === 0) {
		return { result: { ok: false, reason: 'not_allowed' } }
	}
	// Delegation: the issuer must hold every inline grant (trivially true for a self-bound downscope).
	if (findUncoveredGrant(issuer.permissions, grants) !== null) {
		return { result: { ok: false, reason: 'not_allowed' } }
	}

	const token = `${API_KEY_PREFIX}${generateToken()}`
	const id = await services.db.createCredential({
		tokenHash: await hashToken(token),
		label: input.label ?? null,
		principalId: input.principalId ?? null,
		issuedBy: issuer.id,
		expiresAt: input.expiresAt ?? null,
		grants: grants.map((g) => ({ action: g.action, scopeType: g.scope?.type ?? null, scopeValue: g.scope?.value ?? null })),
	})
	return { result: { ok: true, token, id, principalId: input.principalId }, auditLabel: input.label }
}

// ── issueJwt ──────────────────────────────────────────────────────────────────

export async function issueJwt(
	services: Services,
	env: MintEnv,
	input: IssueJwtInput,
	issuer: Issuer,
): Promise<{ result: IssueJwtResult; auditLabel?: string }> {
	if (input.permissions.length === 0) {
		return { result: { ok: false, reason: 'not_allowed' } }
	}
	if (findUncoveredGrant(issuer.permissions, input.permissions) !== null) {
		return { result: { ok: false, reason: 'not_allowed' } }
	}

	const now = Math.floor(Date.now() / 1000)
	const ttl = Math.min(input.ttl ?? DEFAULT_TOKEN_TTL_SECONDS, MAX_PASSTHROUGH_TTL_SECONDS)
	const expiresAt = now + Math.max(1, ttl)
	// A fresh subject id is the audit reference (there is no DB row); the token is anonymous (no ptype).
	const id = uuidv7()
	const token = await signAccessToken(services, env, {
		app: input.app,
		subject: id,
		label: input.label ?? null,
		permissions: input.permissions.map(grantToEntry),
		issuedAt: now,
		expiresAt,
	})
	return { result: { ok: true, token, expiresAt, id }, auditLabel: input.label }
}

// ── revokeKey ───────────────────────────────────────────────────────────────────

/** A `credential_grants` row → a delegation-check `KeyGrant` (both scope cols null = global). */
function credentialGrantToKeyGrant(row: CredentialGrantRow): KeyGrant {
	const scope = row.scope_type === null || row.scope_value === null ? null : { type: row.scope_type, value: row.scope_value }
	return { action: row.action, scope }
}

/**
 * Revoke an opaque `px_` credential by id. Authorization mirrors the old capability revoke: the
 * original issuer may always revoke; otherwise, for an ANONYMOUS credential (a share link), the caller
 * must be able to re-issue its grants — hold every granted action, checked with the same
 * `findUncoveredGrant` as issue. A principal-bound credential is managed through the principal path
 * (the api-keys page), so a non-issuer caller cannot revoke it by id here. Idempotent — a
 * second revoke returns `{ ok: true, revoked: false }`; an unknown id → `not_found`.
 */
export async function revokeKey(services: Services, input: RevokeKeyInput, revoker: Issuer): Promise<RevokeKeyResult> {
	const cred = await services.db.getCredentialById(input.id)
	if (!cred) {
		return { ok: false, reason: 'not_found' }
	}
	if (cred.issued_by !== revoker.id) {
		if (cred.principal_id !== null) {
			return { ok: false, reason: 'not_allowed' }
		}
		const grants = (await services.db.getCredentialGrants(cred.id)).map(credentialGrantToKeyGrant)
		if (findUncoveredGrant(revoker.permissions, grants) !== null) {
			return { ok: false, reason: 'not_allowed' }
		}
	}
	const revoked = await services.db.revokeCredential(cred.id)
	return { ok: true, revoked }
}
