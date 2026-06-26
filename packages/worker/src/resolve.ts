import type { PermissionEntry, PermissionSource, RoleDef, RoleSource, Scope } from '@propustka/core'
import type { Db, GrantRow, PrincipalRow, RoleRow } from './db'
import { parseJson } from './json'
import { makeRoleSource } from './roles'

// ── Pure resolution (no I/O) — testable with in-memory rows ───────────────────

/**
 * The explicit grants already fetched as rows, plus the bootstrap decision.
 * `computePermissions` is pure over this, so the union/dedup logic is
 * unit-testable without D1.
 */
export interface ResolutionInputs {
	/** The calling app — passed to `RoleSource.getRole`; null = cross-app. */
	app: string | null
	/** Active, non-expired explicit grants for this principal. */
	grants: GrantRow[]
	/** True when the user's email is in IAM_BOOTSTRAP_ADMINS (false for services). */
	isBootstrapAdmin: boolean
}

/**
 * Reconstruct the flat scope coordinate from a row's `scope_type`/`scope_value`. Both
 * are NULL together (= global, `scope: null`) by the migration's both-or-neither
 * CHECK; a half-set pair can't exist, but we guard on `scope_type` to stay total.
 */
function rowScope(scopeType: string | null, scopeValue: string | null): Scope | null {
	return scopeType === null || scopeValue === null ? null : { type: scopeType, value: scopeValue }
}

/**
 * Parse a grant's inline `permissions` JSON into an array of action patterns. The
 * migration's `json_valid` CHECK keeps malformed JSON out at write time; a row whose
 * JSON isn't a string array (shouldn't happen) yields no patterns (fail-closed).
 */
function inlinePatterns(json: string): string[] {
	const parsed = parseJson(json)
	if (!Array.isArray(parsed)) {
		return []
	}
	return parsed.filter((p): p is string => typeof p === 'string')
}

/**
 * Union the permission sources, expanding role keys into permission patterns via the
 * (app-aware) role source and adding inline grant patterns directly, then dedupe.
 * Wildcards (`*`, `prefix.*`) stay as patterns in the entries — they are NOT
 * pre-expanded; `permits()` in core matches them. A grant whose role key no longer
 * resolves contributes zero permissions (fail-closed).
 *
 * Resolution is PURE: `roles` is built up front from the app's loaded DB rows, so no
 * I/O happens here. Dedup key is `action|scope|source` — the same permission from two
 * sources is kept separately so the admin UI can explain *why* a permission is held;
 * `can()` / `scopedTo()` ignore `source` anyway.
 */
export function computePermissions(inputs: ResolutionInputs, roles: RoleSource): PermissionEntry[] {
	const entries: PermissionEntry[] = []
	const seen = new Set<string>()

	const add = (action: string, scope: Scope | null, source: PermissionSource): void => {
		const scopeKey = scope === null ? '' : `${scope.type}:${scope.value}`
		const key = `${action} ${scopeKey} ${source}`
		if (seen.has(key)) {
			return
		}
		seen.add(key)
		entries.push({ action, scope, source })
	}

	const expandRole = (roleKey: string, scope: Scope | null, source: PermissionSource): void => {
		const role = roles.getRole(inputs.app, roleKey)
		if (!role) {
			// Dangling role key — resolves to zero permissions (fail-closed).
			return
		}
		for (const permission of role.permissions) {
			add(permission, scope, source)
		}
	}

	// 1. Explicit grants — EITHER a named role OR an inline action-pattern set.
	for (const grant of inputs.grants) {
		const scope = rowScope(grant.scope_type, grant.scope_value)
		if (grant.role_key !== null) {
			expandRole(grant.role_key, scope, 'grant')
		} else if (grant.permissions !== null) {
			for (const pattern of inlinePatterns(grant.permissions)) {
				add(pattern, scope, 'grant')
			}
		}
	}

	// 2. Bootstrap admins (users only) — the built-in global `admin` role, source
	// 'bootstrap'. `admin` is a cross-app built-in, so it resolves even at app=null.
	if (inputs.isBootstrapAdmin) {
		expandRole('admin', null, 'bootstrap')
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

// ── Full resolution wiring (grants ∪ bootstrap) ───────────────────────────────

/**
 * Load the calling app's DB roles into a `RoleSource` (built-ins layered over them).
 * `app === null` (cross-app, e.g. the local-dev bypass / a NULL-app token) has no
 * per-app rows to load — only the built-in `admin` applies. Roles are fetched HERE,
 * up front, so `computePermissions` stays pure: its parsed permission arrays are
 * cached in the returned `RoleSource`'s map and never re-read from D1.
 */
async function loadRoleSource(db: Db, app: string | null): Promise<RoleSource> {
	const appRoles: Record<string, RoleDef> = {}
	if (app !== null) {
		for (const row of await db.listRoles(app)) {
			appRoles[row.role_key] = toRoleDef(row)
		}
	}
	return makeRoleSource(appRoles)
}

/** A `roles` row → core `RoleDef`. `permissions` parses from its JSON-array column. */
function toRoleDef(row: RoleRow): RoleDef {
	return {
		name: row.name,
		...(row.description !== null ? { description: row.description } : {}),
		permissions: inlinePatterns(row.permissions),
	}
}

/**
 * Fetch a user's explicit grants and compute their permissions (grants ∪ bootstrap). The calling
 * app's roles are loaded once and passed to the pure `computePermissions`. Users authenticate via
 * propustka's own OIDC session — there are no IdP groups in the permission decision.
 */
export async function resolveUserPermissions(args: {
	db: Db
	principal: PrincipalRow
	bootstrapAdmins: ReadonlySet<string>
	/** Calling app; grants are filtered to it (or NULL = cross-app). */
	app: string | null
}): Promise<PermissionEntry[]> {
	const { db, principal, bootstrapAdmins, app } = args

	const grants = await db.getActiveGrantsForApp(principal.id, app)
	const isBootstrapAdmin = principal.email !== null && bootstrapAdmins.has(principal.email)

	const roles = await loadRoleSource(db, app)
	return computePermissions({ app, grants, isBootstrapAdmin }, roles)
}

/**
 * Service principals: explicit grants only — no bootstrap — scoped to the calling app
 * (NULL = cross-app).
 */
export async function resolveServicePermissions(db: Db, principal: PrincipalRow, app: string | null): Promise<PermissionEntry[]> {
	const grants = await db.getActiveGrantsForApp(principal.id, app)
	const roles = await loadRoleSource(db, app)
	return computePermissions({ app, grants, isBootstrapAdmin: false }, roles)
}
