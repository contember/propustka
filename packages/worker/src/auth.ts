import type { AuthenticateInput, AuthenticateResult, PermissionEntry } from '@propustka/core'
import { principalStatus } from './db'
import { resolveServicePermissions, resolveUserPermissions, resolveUserPrincipal } from './resolve'
import type { Services } from './services'

/**
 * The shared authentication flow: validate the forwarded Access JWT, resolve the
 * principal, and compute its permissions. Used by `authenticate()` (RPC), the
 * admin gate, and `issueCapability()` (which resolves the *issuer*). Aims to never
 * throw — returns a structured `AuthenticateResult` for every expected outcome,
 * including the lazy-create/claim races (recovered in `resolveUserPrincipal`). A
 * transient D1 error on a read can still propagate; callers (`authenticate()` /
 * `issueCapability()`) backstop that, failing closed and still writing an auth-log
 * row, so an unexpected throw never becomes a 500.
 *
 * The result includes the verified app id (aud-derived) and whether group
 * resolution was unavailable, alongside the standard AuthenticateResult — callers
 * use these for the auth-log row and the `groupsUnavailable` flag.
 */
export interface ResolveOutcome {
	result: AuthenticateResult
	/** Verified app id (aud-derived) on a valid token; null when no valid token. */
	verifiedApp: string | null
	/** Finer-grained reason for the auth log (e.g. 'aud_not_configured'). */
	logReason: string | null
	groupsUnavailable: boolean
}

/**
 * Fixed identity for the local dev bypass below. A row with this id is seeded into
 * `principals` (see `seed.dev.sql`) so audit/auth-log foreign keys resolve.
 */
export const LOCAL_DEV_ADMIN_ID = 'local-dev-admin'

export async function resolveRequest(services: Services, input: AuthenticateInput): Promise<ResolveOutcome> {
	// LOCAL DEV BYPASS. There is no Cloudflare Access in front of `lopata`/`wrangler dev`, so no
	// JWT is forwarded and the admin UI + example app would be unusable. When ENVIRONMENT='local'
	// AND no token was presented, resolve a fixed global-admin identity. Strictly local: a real
	// token (if one is somehow present) still validates normally below, so stage/prod NEVER reach
	// this branch. Mirrors opice's "local is open" dev mode.
	//
	// Defense in depth: also require that NO real Access is configured (ACCESS_APPS empty). Local
	// sets ACCESS_APPS='{}' (see oblaka.ts); any real stage/prod deploy has a non-empty audience
	// map. So even a mis-pinned ENVIRONMENT='local' (e.g. a stale committed wrangler.jsonc deployed
	// directly) cannot enable unauthenticated global admin — the bypass stays impossible to trigger
	// wherever Access actually fronts the Worker.
	if (
		services.config.environment === 'local'
		&& input.token === null
		&& Object.keys(services.config.accessApps).length === 0
	) {
		// A visible signal: this should only ever fire in local dev. If it appears in a real
		// deployment's logs, ENVIRONMENT is mis-set and must be fixed.
		console.warn('local dev bypass active: resolving fixed global-admin identity (ENVIRONMENT=local, no Access configured)')
		return {
			result: {
				ok: true,
				principal: {
					id: LOCAL_DEV_ADMIN_ID,
					type: 'user',
					label: 'local-dev-admin',
					permissions: [{ action: '*', projectId: null, source: 'bootstrap' }],
					requestId: input.requestId,
				},
			},
			verifiedApp: null,
			logReason: 'local_bypass',
			groupsUnavailable: false,
		}
	}

	const validation = await services.jwt.validate(input.token)
	if (!validation.ok) {
		return {
			result: { ok: false, reason: validation.reason },
			verifiedApp: null,
			logReason: validation.logReason,
			groupsUnavailable: false,
		}
	}

	const verifiedApp = validation.app

	if (validation.kind === 'service') {
		// Service principals are never invited / lazily created — an unknown
		// common_name is unknown_principal.
		const principal = await services.db.getServiceByExternalId(validation.commonName)
		if (!principal) {
			return { result: { ok: false, reason: 'unknown_principal' }, verifiedApp, logReason: null, groupsUnavailable: false }
		}
		if (principalStatus(principal) === 'disabled') {
			return { result: { ok: false, reason: 'disabled' }, verifiedApp, logReason: null, groupsUnavailable: false }
		}
		const permissions = await resolveServicePermissions(services.db, principal)
		return {
			result: {
				ok: true,
				principal: {
					id: principal.id,
					type: 'service',
					label: principal.label,
					permissions,
					requestId: input.requestId,
				},
			},
			verifiedApp,
			logReason: null,
			groupsUnavailable: false,
		}
	}

	// User: 3-step claim-then-lazy resolution.
	const resolved = await resolveUserPrincipal(services.db, validation.sub, validation.email)
	if (!resolved.ok) {
		return { result: { ok: false, reason: resolved.reason }, verifiedApp, logReason: null, groupsUnavailable: false }
	}
	const principal = resolved.principal

	const { permissions, groupsUnavailable } = await resolveUserPermissions({
		db: services.db,
		identity: services.identity,
		principal,
		cookie: input.cookie,
		origin: input.origin,
		bootstrapAdmins: services.config.bootstrapAdmins,
	})

	const result: AuthenticateResult = {
		ok: true,
		principal: {
			id: principal.id,
			type: 'user',
			label: principal.label,
			permissions,
			requestId: input.requestId,
		},
		...(groupsUnavailable ? { groupsUnavailable: true as const } : {}),
	}
	return { result, verifiedApp, logReason: groupsUnavailable ? 'groups_unavailable' : null, groupsUnavailable }
}

/** Pull `{ id, permissions }` out of a successful outcome for the issuer/admin gate. */
export function principalFromOutcome(outcome: ResolveOutcome): { id: string; permissions: PermissionEntry[] } | null {
	if (!outcome.result.ok) {
		return null
	}
	return { id: outcome.result.principal.id, permissions: outcome.result.principal.permissions }
}
