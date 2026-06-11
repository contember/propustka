import type { PermissionEntry, PermissionSource, RoleSource } from '@propustka/core'
import type { Db, GrantRow, GroupMappingRow, PrincipalRow } from './db'
import type { IdentityClient } from './identity'
import { codeRoleSource } from './roles'

const GITHUB_PROVIDER = 'github'

// ── Pure resolution (no I/O) — testable with in-memory rows ───────────────────

/**
 * The three permission sources already fetched as rows, plus the bootstrap
 * decision. `computePermissions` is pure over this, so the union/dedup logic is
 * unit-testable without D1 or get-identity.
 */
export interface ResolutionInputs {
	/** Active, non-expired explicit grants for this principal. */
	grants: GrantRow[]
	/** Group mappings matched against the user's group refs (empty for services). */
	groupMappings: { mapping: GroupMappingRow; groupRef: string }[]
	/** True when the user's email is in IAM_BOOTSTRAP_ADMINS (false for services). */
	isBootstrapAdmin: boolean
}

/**
 * Union the three permission sources, expanding role keys into permission
 * patterns via the role registry, and dedupe. Wildcards (`*`, `prefix.*`) stay as
 * patterns in the entries — they are NOT pre-expanded; `permits()` in core matches
 * them. A grant whose role key no longer exists resolves to zero permissions
 * (fail-closed).
 *
 * Dedup key is `action|projectId|source` — the same permission from two sources is
 * kept separately so the admin UI can explain *why* a permission is held; `can()`
 * / `scopedTo()` ignore `source` anyway.
 */
export function computePermissions(inputs: ResolutionInputs, roles: RoleSource = codeRoleSource): PermissionEntry[] {
	const entries: PermissionEntry[] = []
	const seen = new Set<string>()

	const add = (action: string, projectId: string | null, source: PermissionSource): void => {
		const key = `${action} ${projectId ?? ''} ${source}`
		if (seen.has(key)) {
			return
		}
		seen.add(key)
		entries.push({ action, projectId, source })
	}

	const expand = (roleKey: string, projectId: string | null, source: PermissionSource): void => {
		const role = roles.getRole(roleKey)
		if (!role) {
			// Dangling role key — resolves to zero permissions (fail-closed).
			return
		}
		for (const permission of role.permissions) {
			add(permission, projectId, source)
		}
	}

	// 1. Explicit grants.
	for (const grant of inputs.grants) {
		expand(grant.role_key, grant.project_id, 'grant')
	}

	// 2. Group-derived roles (users only — services pass an empty list).
	for (const { mapping, groupRef } of inputs.groupMappings) {
		expand(mapping.role_key, mapping.project_id, `group:${groupRef}`)
	}

	// 3. Bootstrap admins (users only) — a global `admin` role, source 'bootstrap'.
	if (inputs.isBootstrapAdmin) {
		expand('admin', null, 'bootstrap')
	}

	return entries
}

// ── Principal resolution (the 3-step claim-then-lazy flow) ────────────────────

export type ResolveUserResult =
	| { ok: true; principal: PrincipalRow }
	| { ok: false; reason: 'disabled' | 'unknown_principal' }

/**
 * The narrow slice of `Db` that user-principal resolution needs. Declaring it here
 * (rather than taking the whole `Db`) keeps the 3-step flow unit-testable with an
 * in-memory store, no `as` cast required. `Db` structurally satisfies it.
 */
export interface UserPrincipalStore {
	getUserByExternalId(sub: string): Promise<PrincipalRow | null>
	getUserByEmail(email: string): Promise<PrincipalRow | null>
	refreshUserLabel(id: string, email: string): Promise<void>
	claimInvitedUser(id: string, sub: string, email: string): Promise<PrincipalRow | null>
	createUser(sub: string, email: string): Promise<PrincipalRow>
}

/**
 * Resolve (or claim/create) a user principal from a verified identity-login JWT.
 * Ordered: (1) by `sub`; (2) claim an invited row matched on the IdP-verified
 * `email`; (3) lazy-create. Matching uses ONLY the verified token email — never a
 * self-asserted value. A disabled match returns `disabled` (403). An email that
 * already belongs to a *different* claimed sub is a conflict → `unknown_principal`
 * (fail-closed; the unique-email index forbids a second user, so we never insert).
 */
export async function resolveUserPrincipal(db: UserPrincipalStore, sub: string, email: string): Promise<ResolveUserResult> {
	// 1. By sub — a returning user. Refresh email/label if the token's email changed.
	const bySub = await db.getUserByExternalId(sub)
	if (bySub) {
		if (bySub.disabled_at !== null) {
			return { ok: false, reason: 'disabled' }
		}
		if (bySub.email !== email || bySub.label !== email) {
			try {
				await db.refreshUserLabel(bySub.id, email)
			} catch (err) {
				// Non-fatal: the new token email may collide with another principal's
				// unique-email row. This user is already a known principal by sub, so a
				// cosmetic label refresh must never lock them out — keep serving the
				// existing identity (its current email/label) and skip the refresh.
				console.warn(`refreshUserLabel skipped for principal ${bySub.id} (email collision on '${email}')`, err)
				return { ok: true, principal: bySub }
			}
		}
		return { ok: true, principal: { ...bySub, email, label: email } }
	}

	// 2. Match the verified email.
	const byEmail = await db.getUserByEmail(email)
	if (byEmail) {
		if (byEmail.external_id === null) {
			// An invited row — claim it.
			if (byEmail.disabled_at !== null) {
				// An invited-but-disabled principal — treat as not allowed.
				return { ok: false, reason: 'disabled' }
			}
			const claimed = await db.claimInvitedUser(byEmail.id, sub, email)
			if (claimed) {
				return { ok: true, principal: claimed }
			}
			// Lost the claim race — re-read by sub (the winner bound the same sub).
			const reread = await db.getUserByExternalId(sub)
			if (reread) {
				if (reread.disabled_at !== null) {
					return { ok: false, reason: 'disabled' }
				}
				return { ok: true, principal: reread }
			}
		}
		// The email belongs to a row already claimed by a DIFFERENT sub (step 1 didn't
		// match this sub). The unique-email index forbids a second user — fail closed.
		// Narrow window per spec (email reassigned before first login); mitigate with
		// invite expiry later (out of scope v1).
		return { ok: false, reason: 'unknown_principal' }
	}

	// 3. Lazy-create, zero grants — unprivileged until granted or matched.
	try {
		const created = await db.createUser(sub, email)
		return { ok: true, principal: created }
	} catch (err) {
		// Lazy-create race: two concurrent first logins for the same brand-new sub both
		// miss steps 1 & 2, then both INSERT. The second hits the partial unique index
		// (idx_principals_uq_external / idx_principals_uq_email) and D1 throws. Recover
		// exactly like the step-2 claim race: re-read by sub and serve the winner
		// (honoring its disabled_at). If the re-read still finds nothing, fail closed.
		const reread = await db.getUserByExternalId(sub)
		if (reread) {
			if (reread.disabled_at !== null) {
				return { ok: false, reason: 'disabled' }
			}
			return { ok: true, principal: reread }
		}
		console.warn(`createUser failed and no row found on re-read for sub '${sub}'`, err)
		return { ok: false, reason: 'unknown_principal' }
	}
}

// ── Full resolution wiring (grants ∪ groups ∪ bootstrap) ──────────────────────

export interface ResolvedPermissions {
	permissions: PermissionEntry[]
	groupsUnavailable: boolean
}

/**
 * Fetch the three sources for a user and compute their permissions. Group
 * resolution uses get-identity; an outage degrades to explicit grants only with
 * `groupsUnavailable: true` (still fail-closed on the *permission* decision).
 */
export async function resolveUserPermissions(args: {
	db: Db
	identity: IdentityClient
	principal: PrincipalRow
	cookie: string | null
	origin: string | null
	bootstrapAdmins: ReadonlySet<string>
	/** Verified calling app (aud-derived); grants/mappings are filtered to it (or NULL = cross-app). */
	app: string | null
}): Promise<ResolvedPermissions> {
	const { db, identity, principal, cookie, origin, bootstrapAdmins, app } = args

	const grants = await db.getActiveGrantsForApp(principal.id, app)

	const groupResult = await identity.getGroups(principal.id, cookie, origin)
	let groupMappings: { mapping: GroupMappingRow; groupRef: string }[] = []
	if (!groupResult.unavailable && groupResult.groups.length > 0) {
		const mappings = await db.getMappingsForGroups(GITHUB_PROVIDER, groupResult.groups, app)
		groupMappings = mappings.map((mapping) => ({ mapping, groupRef: mapping.group_ref }))
	}

	const isBootstrapAdmin = principal.email !== null && bootstrapAdmins.has(principal.email)

	const permissions = computePermissions({ grants, groupMappings, isBootstrapAdmin })
	return { permissions, groupsUnavailable: groupResult.unavailable }
}

/**
 * Service principals: explicit grants only — no groups, no bootstrap — scoped to the
 * calling app (NULL = cross-app).
 */
export async function resolveServicePermissions(db: Db, principal: PrincipalRow, app: string | null): Promise<PermissionEntry[]> {
	const grants = await db.getActiveGrantsForApp(principal.id, app)
	return computePermissions({ grants, groupMappings: [], isBootstrapAdmin: false })
}
