import { uuidv7 } from '@propustka/core'

// ── D1 row shapes (snake_case, as the migration defines) ──────────────────────

export interface PrincipalRow {
	id: string
	type: 'user' | 'service'
	external_id: string | null
	email: string | null
	label: string
	disabled_at: number | null
	created_at: number
}

export interface GrantRow {
	id: string
	principal_id: string
	/** App id (ACCESS_APPS value) this grant applies to; NULL = all apps (cross-app). */
	app: string | null
	/** Named role/policy key; XOR `permissions`. Exactly one is non-null. */
	role_key: string | null
	/** Inline action-pattern set (JSON array); XOR `role_key`. Exactly one is non-null. */
	permissions: string | null
	/** Scope dimension; NULL = global (both scope columns rise/fall together). */
	scope_type: string | null
	/** Opaque, app-owned scope value; NULL = global. */
	scope_value: string | null
	granted_by: string | null
	expires_at: number | null
	created_at: number
}

export interface GroupMappingRow {
	id: string
	provider: string
	group_ref: string
	role_key: string
	/** App id this mapping applies to; NULL = all apps. */
	app: string | null
	/** Scope dimension; NULL = global. */
	scope_type: string | null
	/** Opaque, app-owned scope value; NULL = global. */
	scope_value: string | null
	created_at: number
}

/** A role/policy bundle row (the `roles` table). `permissions` is a JSON array string. */
export interface RoleRow {
	app: string
	role_key: string
	name: string
	description: string | null
	/** JSON array of action patterns, e.g. '["project.read","report.*"]'. */
	permissions: string
	/** 'app' = reconciled from code, 'custom' = admin-composed. */
	origin: 'app' | 'custom'
	created_at: number
}

/** A scope-dimension row (the `app_scopes` table). */
export interface AppScopeRow {
	app: string
	scope_type: string
	label: string | null
}

/** An action-catalog row (the `app_actions` table). */
export interface AppActionRow {
	app: string
	action: string
	description: string | null
}

export interface AuditEventRow {
	id: string
	request_id: string
	principal_id: string | null
	principal_label: string
	credential_id: string | null
	app: string
	action: string
	resource_type: string
	resource_id: string | null
	diff: string | null
	metadata: string | null
	created_at: number
}

export interface AuthLogRow {
	id: number
	request_id: string
	app: string
	kind: 'authenticate'
	principal_id: string | null
	credential_id: string | null
	decision: 'allow' | 'deny'
	reason: string | null
	created_at: number
}

/** A unified credential row (the `credentials` table). Only the secret's hash is stored. */
export interface CredentialRow {
	id: string
	token_hash: string
	label: string | null
	/** Bound principal (live perms), or NULL for an anonymous (frozen inline-grant) credential. */
	principal_id: string | null
	issued_by: string | null
	expires_at: number | null
	revoked_at: number | null
	created_at: number
}

/** One inline grant on a credential (the `credential_grants` table). Matched by `permits`. */
export interface CredentialGrantRow {
	credential_id: string
	action: string
	scope_type: string | null
	scope_value: string | null
}

/** An SSO session row (the `sessions` table). Only the cookie's hash is stored, never plaintext. */
export interface SessionRow {
	id: string
	token_hash: string
	principal_id: string
	idp_sub: string
	email: string | null
	created_at: number
	expires_at: number
	revoked_at: number | null
}

/** Derived principal status — invited (unclaimed) → active → disabled. */
export type PrincipalStatus = 'invited' | 'active' | 'disabled'

export function principalStatus(row: PrincipalRow): PrincipalStatus {
	if (row.disabled_at !== null) {
		return 'disabled'
	}
	// Only a USER has the invite lifecycle (external_id NULL = invited, not yet claimed). A service
	// principal is native (external_id NULL by construction) and is 'active' from creation.
	if (row.type === 'user' && row.external_id === null) {
		return 'invited'
	}
	return 'active'
}

// Inputs that audit/auth-log writes accept (the Worker stamps ids/timestamps).
export interface AuditEventInput {
	requestId: string
	principalId: string | null
	principalLabel: string
	credentialId?: string | null
	app: string
	action: string
	resourceType: string
	resourceId?: string | null
	diff?: unknown
	metadata?: unknown
}

export interface AuthLogInput {
	requestId: string
	app: string
	kind: 'authenticate'
	principalId: string | null
	credentialId?: string | null
	decision: 'allow' | 'deny'
	reason?: string | null
}

/**
 * Run a statement that always returns exactly one row (an `INSERT/UPDATE … RETURNING`
 * we know matched). `.first<T>()` is typed `T | null`; this narrows it to `T`,
 * throwing if the row is unexpectedly absent (a programming/DB error, not normal flow).
 */
async function firstRow<T>(statement: D1PreparedStatement): Promise<T> {
	const row = await statement.first<T>()
	if (row === null) {
		throw new Error('expected a row from a RETURNING statement, got none')
	}
	return row
}

/**
 * All D1 access. Prepared statements via `db.prepare(...).bind(...)`. Grouped by
 * the modules that need them: principals (resolve/admin), grants, group mappings,
 * credentials (API keys / share links), sessions, and the two write-only audit tables.
 */
export class Db {
	constructor(private readonly d1: D1Database) {}

	// ── Principals ──────────────────────────────────────────────────────────

	async getUserByExternalId(sub: string): Promise<PrincipalRow | null> {
		return this.d1
			.prepare(`SELECT * FROM principals WHERE type = 'user' AND external_id = ?`)
			.bind(sub)
			.first<PrincipalRow>()
	}

	async getServiceByExternalId(commonName: string): Promise<PrincipalRow | null> {
		return this.d1
			.prepare(`SELECT * FROM principals WHERE type = 'service' AND external_id = ?`)
			.bind(commonName)
			.first<PrincipalRow>()
	}

	async getPrincipalById(id: string): Promise<PrincipalRow | null> {
		return this.d1.prepare('SELECT * FROM principals WHERE id = ?').bind(id).first<PrincipalRow>()
	}

	async getUserByEmail(email: string): Promise<PrincipalRow | null> {
		return this.d1
			.prepare(`SELECT * FROM principals WHERE type = 'user' AND email = ?`)
			.bind(email)
			.first<PrincipalRow>()
	}

	/** Refresh a returning user's email/label if the token's email changed. No-op when unchanged. */
	async refreshUserLabel(id: string, email: string): Promise<void> {
		await this.d1
			.prepare('UPDATE principals SET email = ?, label = ? WHERE id = ? AND (email IS NOT ? OR label IS NOT ?)')
			.bind(email, email, id, email, email)
			.run()
	}

	/**
	 * Claim an invited row in one statement: bind `external_id = sub`, set
	 * `label = email`, but only while still unclaimed (`external_id IS NULL`) to
	 * avoid a race claiming a row twice. Returns the claimed row, or null if the
	 * row was concurrently claimed / not found.
	 */
	async claimInvitedUser(id: string, sub: string, email: string): Promise<PrincipalRow | null> {
		return this.d1
			.prepare(`UPDATE principals SET external_id = ?, label = ?
				WHERE id = ? AND type = 'user' AND external_id IS NULL
				RETURNING *`)
			.bind(sub, email, id)
			.first<PrincipalRow>()
	}

	/** Lazy-create a user keyed by the verified `sub`. */
	async createUser(sub: string, email: string): Promise<PrincipalRow> {
		const id = uuidv7()
		return firstRow<PrincipalRow>(
			this.d1
				.prepare(`INSERT INTO principals (id, type, external_id, email, label)
					VALUES (?, 'user', ?, ?, ?) RETURNING *`)
				.bind(id, sub, email, email),
		)
	}

	/** Invite a user by email (external_id NULL = unclaimed). */
	async inviteUser(email: string): Promise<PrincipalRow> {
		const id = uuidv7()
		return firstRow<PrincipalRow>(
			this.d1
				.prepare(`INSERT INTO principals (id, type, external_id, email, label)
					VALUES (?, 'user', NULL, ?, ?) RETURNING *`)
				.bind(id, email, email),
		)
	}

	/**
	 * Create a native service (machine) principal. `external_id` is NULL — a native service is resolved
	 * through its `px_` credential (credential.principal_id → principal), never an external id. (The
	 * legacy CF service-token path still resolves existing services by their stored external_id.)
	 */
	async createService(label: string): Promise<PrincipalRow> {
		const id = uuidv7()
		return firstRow<PrincipalRow>(
			this.d1
				.prepare(`INSERT INTO principals (id, type, external_id, email, label)
					VALUES (?, 'service', NULL, NULL, ?) RETURNING *`)
				.bind(id, label),
		)
	}

	async listPrincipals(filter: { type?: 'user' | 'service'; q?: string }): Promise<PrincipalRow[]> {
		const where: string[] = []
		const binds: (string | number)[] = []
		if (filter.type) {
			where.push('type = ?')
			binds.push(filter.type)
		}
		if (filter.q) {
			where.push('(label LIKE ? OR email LIKE ?)')
			binds.push(`%${filter.q}%`, `%${filter.q}%`)
		}
		const sql = `SELECT * FROM principals${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY created_at DESC`
		const { results } = await this.d1.prepare(sql).bind(...binds).all<PrincipalRow>()
		return results
	}

	/**
	 * The USER principals who can access `app` — every user holding at least one non-expired
	 * grant that applies to the app (the grant's `app` is NULL = cross-app, OR equals `app`).
	 * `DISTINCT` collapses the per-grant duplicates a principal with several grants produces.
	 * Services are excluded — this is the people directory (assignable users / actor labels),
	 * not machine principals. Disabled users ARE returned (the caller decides whether to hide
	 * them) so their labels still resolve. Ordered by label for a stable picker.
	 */
	async getPrincipalsForApp(app: string): Promise<PrincipalRow[]> {
		const { results } = await this.d1
			.prepare(`SELECT DISTINCT p.* FROM principals p
				JOIN grants g ON g.principal_id = p.id
				WHERE p.type = 'user'
					AND (g.app IS NULL OR g.app = ?)
					AND (g.expires_at IS NULL OR g.expires_at > unixepoch())
				ORDER BY p.label`)
			.bind(app)
			.all<PrincipalRow>()
		return results
	}

	async disablePrincipal(id: string): Promise<boolean> {
		const result = await this.d1
			.prepare('UPDATE principals SET disabled_at = unixepoch() WHERE id = ? AND disabled_at IS NULL')
			.bind(id)
			.run()
		return (result.meta.changes ?? 0) > 0
	}

	async enablePrincipal(id: string): Promise<boolean> {
		const result = await this.d1
			.prepare('UPDATE principals SET disabled_at = NULL WHERE id = ? AND disabled_at IS NOT NULL')
			.bind(id)
			.run()
		return (result.meta.changes ?? 0) > 0
	}

	/** Hard-delete a principal (cancels an unclaimed invite; cascades grants). */
	async deletePrincipal(id: string): Promise<boolean> {
		const result = await this.d1.prepare('DELETE FROM principals WHERE id = ?').bind(id).run()
		return (result.meta.changes ?? 0) > 0
	}

	// ── Grants ──────────────────────────────────────────────────────────────

	/** Active (non-expired) grants for a principal, ALL apps (admin/effective view). */
	async getActiveGrants(principalId: string): Promise<GrantRow[]> {
		const { results } = await this.d1
			.prepare(`SELECT * FROM grants
				WHERE principal_id = ? AND (expires_at IS NULL OR expires_at > unixepoch())`)
			.bind(principalId)
			.all<GrantRow>()
		return results
	}

	/**
	 * Active grants that apply to the calling `app` — the authz path. A grant counts
	 * when its `app` is NULL (cross-app) OR equals the verified calling app. When `app`
	 * is null (no verified app), only cross-app (NULL) grants match — fail-safe.
	 */
	async getActiveGrantsForApp(principalId: string, app: string | null): Promise<GrantRow[]> {
		const { results } = await this.d1
			.prepare(`SELECT * FROM grants
				WHERE principal_id = ?
					AND (app IS NULL OR app = ?)
					AND (expires_at IS NULL OR expires_at > unixepoch())`)
			.bind(principalId, app)
			.all<GrantRow>()
		return results
	}

	/** All grants for a principal (admin view, incl. expired). */
	async listGrants(principalId: string): Promise<GrantRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM grants WHERE principal_id = ? ORDER BY created_at DESC')
			.bind(principalId)
			.all<GrantRow>()
		return results
	}

	async getGrantById(id: string): Promise<GrantRow | null> {
		return this.d1.prepare('SELECT * FROM grants WHERE id = ?').bind(id).first<GrantRow>()
	}

	/**
	 * Create a grant. EITHER `roleKey` (named role/policy) OR `permissions` (an inline
	 * action-pattern set, JSON-encoded here) — the caller MUST supply exactly one; the
	 * DB CHECK rejects both/neither. `scopeType`/`scopeValue` are both-or-neither (both
	 * null = global). The handler validates which is set; this layer just persists it.
	 */
	async createGrant(input: {
		principalId: string
		app?: string | null
		roleKey?: string | null
		permissions?: string[] | null
		scopeType?: string | null
		scopeValue?: string | null
		grantedBy?: string | null
		expiresAt?: number | null
	}): Promise<GrantRow> {
		const id = uuidv7()
		return firstRow<GrantRow>(
			this.d1
				.prepare(`INSERT INTO grants (id, principal_id, app, role_key, permissions, scope_type, scope_value, granted_by, expires_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *`)
				.bind(
					id,
					input.principalId,
					input.app ?? null,
					input.roleKey ?? null,
					input.permissions == null ? null : JSON.stringify(input.permissions),
					input.scopeType ?? null,
					input.scopeValue ?? null,
					input.grantedBy ?? null,
					input.expiresAt ?? null,
				),
		)
	}

	async deleteGrant(id: string): Promise<boolean> {
		const result = await this.d1.prepare('DELETE FROM grants WHERE id = ?').bind(id).run()
		return (result.meta.changes ?? 0) > 0
	}

	/** Delete all grants for a principal (revocation). */
	async deleteGrantsForPrincipal(principalId: string): Promise<void> {
		await this.d1.prepare('DELETE FROM grants WHERE principal_id = ?').bind(principalId).run()
	}

	// ── Group → role mappings ─────────────────────────────────────────────────

	/**
	 * Mappings matching any of the given normalized group refs (users only),
	 * scoped to the calling `app` (NULL app = cross-app). Mirrors getActiveGrantsForApp.
	 */
	async getMappingsForGroups(provider: string, groupRefs: string[], app: string | null): Promise<GroupMappingRow[]> {
		if (groupRefs.length === 0) {
			return []
		}
		const placeholders = groupRefs.map(() => '?').join(', ')
		const { results } = await this.d1
			.prepare(`SELECT * FROM group_role_mappings
				WHERE provider = ? AND group_ref IN (${placeholders}) AND (app IS NULL OR app = ?)`)
			.bind(provider, ...groupRefs, app)
			.all<GroupMappingRow>()
		return results
	}

	async listGroupMappings(): Promise<GroupMappingRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM group_role_mappings ORDER BY created_at DESC')
			.all<GroupMappingRow>()
		return results
	}

	async createGroupMapping(input: {
		provider: string
		groupRef: string
		roleKey: string
		app?: string | null
		scopeType?: string | null
		scopeValue?: string | null
	}): Promise<GroupMappingRow> {
		const id = uuidv7()
		return firstRow<GroupMappingRow>(
			this.d1
				.prepare(`INSERT INTO group_role_mappings (id, provider, group_ref, role_key, app, scope_type, scope_value)
					VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`)
				.bind(
					id,
					input.provider,
					input.groupRef,
					input.roleKey,
					input.app ?? null,
					input.scopeType ?? null,
					input.scopeValue ?? null,
				),
		)
	}

	async getGroupMappingById(id: string): Promise<GroupMappingRow | null> {
		return this.d1.prepare('SELECT * FROM group_role_mappings WHERE id = ?').bind(id).first<GroupMappingRow>()
	}

	async deleteGroupMapping(id: string): Promise<boolean> {
		const result = await this.d1.prepare('DELETE FROM group_role_mappings WHERE id = ?').bind(id).run()
		return (result.meta.changes ?? 0) > 0
	}

	// ── App-declared vocabulary (roles, scopes, actions) ──────────────────────

	/** Every role row for an app (origin='app' AND origin='custom') — for resolution + listing. */
	async listRoles(app: string): Promise<RoleRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM roles WHERE app = ? ORDER BY role_key')
			.bind(app)
			.all<RoleRow>()
		return results
	}

	/** Role rows for an app filtered by origin — used to list just the app/custom set. */
	async listRolesByOrigin(app: string, origin: 'app' | 'custom'): Promise<RoleRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM roles WHERE app = ? AND origin = ? ORDER BY role_key')
			.bind(app, origin)
			.all<RoleRow>()
		return results
	}

	async getRole(app: string, roleKey: string): Promise<RoleRow | null> {
		return this.d1.prepare('SELECT * FROM roles WHERE app = ? AND role_key = ?').bind(app, roleKey).first<RoleRow>()
	}

	/**
	 * Upsert a single role. `permissions` is JSON-encoded here. ON CONFLICT keeps the
	 * row's PK (app, role_key) and overwrites the mutable columns — origin included, so
	 * a reconcile can (re)assert origin='app' on an existing key. `created_at` is left
	 * untouched on update.
	 */
	async upsertRole(input: {
		app: string
		roleKey: string
		name: string
		description?: string | null
		permissions: string[]
		origin: 'app' | 'custom'
	}): Promise<RoleRow> {
		return firstRow<RoleRow>(
			this.d1
				.prepare(`INSERT INTO roles (app, role_key, name, description, permissions, origin)
					VALUES (?, ?, ?, ?, ?, ?)
					ON CONFLICT (app, role_key) DO UPDATE SET
						name = excluded.name,
						description = excluded.description,
						permissions = excluded.permissions,
						origin = excluded.origin
					RETURNING *`)
				.bind(
					input.app,
					input.roleKey,
					input.name,
					input.description ?? null,
					JSON.stringify(input.permissions),
					input.origin,
				),
		)
	}

	async deleteRole(app: string, roleKey: string): Promise<boolean> {
		const result = await this.d1.prepare('DELETE FROM roles WHERE app = ? AND role_key = ?').bind(app, roleKey).run()
		return (result.meta.changes ?? 0) > 0
	}

	/** The app's action catalog as plain strings — the validation source for patterns. */
	async listActionCatalog(app: string): Promise<string[]> {
		const { results } = await this.d1
			.prepare('SELECT action FROM app_actions WHERE app = ? ORDER BY action')
			.bind(app)
			.all<{ action: string }>()
		return results.map((r) => r.action)
	}

	async listAppScopes(app: string): Promise<AppScopeRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM app_scopes WHERE app = ? ORDER BY scope_type')
			.bind(app)
			.all<AppScopeRow>()
		return results
	}

	async listAppActions(app: string): Promise<AppActionRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM app_actions WHERE app = ? ORDER BY action')
			.bind(app)
			.all<AppActionRow>()
		return results
	}

	/**
	 * Idempotent reconcile of an app's declared vocabulary in one atomic batch: upsert
	 * the given scopes/actions/roles (roles forced to origin='app'), then delete any
	 * origin='app' rows NOT in the incoming set. origin='custom' roles are NEVER touched
	 * (admin-composed policies survive a redeploy). Validation (patterns vs. the new
	 * action catalog) is the caller's job — this layer just writes the reconciled state.
	 */
	async reconcileAppSchema(input: {
		app: string
		scopes: { scopeType: string; label?: string | null }[]
		actions: { action: string; description?: string | null }[]
		roles: { roleKey: string; name: string; description?: string | null; permissions: string[] }[]
	}): Promise<void> {
		const { app } = input
		const statements: D1PreparedStatement[] = []

		// Upsert scopes, then prune app scopes not in the incoming set.
		for (const scope of input.scopes) {
			statements.push(
				this.d1
					.prepare(`INSERT INTO app_scopes (app, scope_type, label) VALUES (?, ?, ?)
						ON CONFLICT (app, scope_type) DO UPDATE SET label = excluded.label`)
					.bind(app, scope.scopeType, scope.label ?? null),
			)
		}
		statements.push(this.pruneNotIn('app_scopes', 'scope_type', app, input.scopes.map((s) => s.scopeType)))

		// Upsert actions, then prune actions not in the incoming set.
		for (const action of input.actions) {
			statements.push(
				this.d1
					.prepare(`INSERT INTO app_actions (app, action, description) VALUES (?, ?, ?)
						ON CONFLICT (app, action) DO UPDATE SET description = excluded.description`)
					.bind(app, action.action, action.description ?? null),
			)
		}
		statements.push(this.pruneNotIn('app_actions', 'action', app, input.actions.map((a) => a.action)))

		// Upsert roles as origin='app', then prune origin='app' roles not in the set.
		// origin='custom' rows are excluded from the prune, so they're preserved.
		for (const role of input.roles) {
			statements.push(
				this.d1
					.prepare(`INSERT INTO roles (app, role_key, name, description, permissions, origin)
						VALUES (?, ?, ?, ?, ?, 'app')
						ON CONFLICT (app, role_key) DO UPDATE SET
							name = excluded.name,
							description = excluded.description,
							permissions = excluded.permissions,
							origin = 'app'`)
					.bind(app, role.roleKey, role.name, role.description ?? null, JSON.stringify(role.permissions)),
			)
		}
		statements.push(this.pruneAppRolesNotIn(app, input.roles.map((r) => r.roleKey)))

		await this.d1.batch(statements)
	}

	/**
	 * Build a DELETE that removes rows for `app` whose `column` is not in `keep`. An
	 * empty `keep` deletes all the app's rows in that table (a schema with no scopes,
	 * say, prunes every prior scope). NULL→placeholder handling is unnecessary here:
	 * every kept value is a concrete string.
	 */
	private pruneNotIn(table: 'app_scopes' | 'app_actions', column: string, app: string, keep: string[]): D1PreparedStatement {
		if (keep.length === 0) {
			return this.d1.prepare(`DELETE FROM ${table} WHERE app = ?`).bind(app)
		}
		const placeholders = keep.map(() => '?').join(', ')
		return this.d1.prepare(`DELETE FROM ${table} WHERE app = ? AND ${column} NOT IN (${placeholders})`).bind(app, ...keep)
	}

	/** Like pruneNotIn but ONLY over origin='app' roles — custom policies are never pruned. */
	private pruneAppRolesNotIn(app: string, keep: string[]): D1PreparedStatement {
		if (keep.length === 0) {
			return this.d1.prepare(`DELETE FROM roles WHERE app = ? AND origin = 'app'`).bind(app)
		}
		const placeholders = keep.map(() => '?').join(', ')
		return this.d1
			.prepare(`DELETE FROM roles WHERE app = ? AND origin = 'app' AND role_key NOT IN (${placeholders})`)
			.bind(app, ...keep)
	}

	// ── Credentials (unified opaque API keys / share links) ───────────────────

	/**
	 * Insert a credential + its inline grant rows (if any) in one batch. Only the hash is stored.
	 * `principalId` null = an anonymous (frozen-grant) credential; non-null = principal-bound.
	 */
	async createCredential(input: {
		tokenHash: string
		label?: string | null
		principalId?: string | null
		issuedBy: string
		expiresAt?: number | null
		grants: { action: string; scopeType?: string | null; scopeValue?: string | null }[]
	}): Promise<string> {
		const id = uuidv7()
		const statements: D1PreparedStatement[] = [
			this.d1
				.prepare(`INSERT INTO credentials (id, token_hash, label, principal_id, issued_by, expires_at)
					VALUES (?, ?, ?, ?, ?, ?)`)
				.bind(id, input.tokenHash, input.label ?? null, input.principalId ?? null, input.issuedBy, input.expiresAt ?? null),
		]
		for (const grant of input.grants) {
			statements.push(
				this.d1
					.prepare('INSERT INTO credential_grants (credential_id, action, scope_type, scope_value) VALUES (?, ?, ?, ?)')
					.bind(id, grant.action, grant.scopeType ?? null, grant.scopeValue ?? null),
			)
		}
		await this.d1.batch(statements)
		return id
	}

	/**
	 * Look up a credential by the secret's hash, but ONLY while still valid (not revoked, not
	 * expired). An invalid/absent credential returns null. Single-statement so the validity check
	 * and the read can't race a concurrent revoke.
	 */
	async getActiveCredentialByHash(tokenHash: string): Promise<CredentialRow | null> {
		return this.d1
			.prepare(`SELECT * FROM credentials
				WHERE token_hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > unixepoch())`)
			.bind(tokenHash)
			.first<CredentialRow>()
	}

	async getCredentialById(id: string): Promise<CredentialRow | null> {
		return this.d1.prepare('SELECT * FROM credentials WHERE id = ?').bind(id).first<CredentialRow>()
	}

	async getCredentialGrants(credentialId: string): Promise<CredentialGrantRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM credential_grants WHERE credential_id = ?')
			.bind(credentialId)
			.all<CredentialGrantRow>()
		return results
	}

	/** Credentials for a principal (admin list / bulk revoke on disable). */
	async listCredentialsForPrincipal(principalId: string): Promise<CredentialRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM credentials WHERE principal_id = ? ORDER BY created_at DESC')
			.bind(principalId)
			.all<CredentialRow>()
		return results
	}

	/** Anonymous credentials — the share links (no bound principal). The admin share-links list. */
	async listAnonymousCredentials(): Promise<CredentialRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM credentials WHERE principal_id IS NULL ORDER BY created_at DESC')
			.all<CredentialRow>()
		return results
	}

	/** Revoke a credential by id (idempotent — already-revoked → false). */
	async revokeCredential(id: string): Promise<boolean> {
		const result = await this.d1
			.prepare('UPDATE credentials SET revoked_at = unixepoch() WHERE id = ? AND revoked_at IS NULL')
			.bind(id)
			.run()
		return (result.meta.changes ?? 0) > 0
	}

	/** Revoke every active credential bound to a principal (key revoke / rotate). Returns the count. */
	async revokeCredentialsForPrincipal(principalId: string): Promise<number> {
		const result = await this.d1
			.prepare('UPDATE credentials SET revoked_at = unixepoch() WHERE principal_id = ? AND revoked_at IS NULL')
			.bind(principalId)
			.run()
		return result.meta.changes ?? 0
	}

	// ── SSO sessions ──────────────────────────────────────────────────────────

	/** Create a session. Only the hash of the opaque cookie value is stored; returns the new id. */
	async createSession(input: {
		tokenHash: string
		principalId: string
		idpSub: string
		email?: string | null
		expiresAt: number
	}): Promise<string> {
		const id = uuidv7()
		await this.d1
			.prepare(`INSERT INTO sessions (id, token_hash, principal_id, idp_sub, email, expires_at)
				VALUES (?, ?, ?, ?, ?, ?)`)
			.bind(id, input.tokenHash, input.principalId, input.idpSub, input.email ?? null, input.expiresAt)
			.run()
		return id
	}

	/**
	 * Look up a session by the cookie's hash, but ONLY while still valid (not revoked, not expired).
	 * An invalid/absent session returns null — the caller re-authenticates. Single-statement so the
	 * validity check and the read can't race a concurrent revoke.
	 */
	async getActiveSessionByHash(tokenHash: string): Promise<SessionRow | null> {
		return this.d1
			.prepare(`SELECT * FROM sessions
				WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > unixepoch()`)
			.bind(tokenHash)
			.first<SessionRow>()
	}

	/** Revoke a session by the cookie's hash (logout). Idempotent — already-revoked → false. */
	async revokeSessionByHash(tokenHash: string): Promise<boolean> {
		const result = await this.d1
			.prepare('UPDATE sessions SET revoked_at = unixepoch() WHERE token_hash = ? AND revoked_at IS NULL')
			.bind(tokenHash)
			.run()
		return (result.meta.changes ?? 0) > 0
	}

	/** Sessions for a principal (admin list / bulk revoke on disable). */
	async listSessionsForPrincipal(principalId: string): Promise<SessionRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM sessions WHERE principal_id = ? ORDER BY created_at DESC')
			.bind(principalId)
			.all<SessionRow>()
		return results
	}

	/** Prune expired or revoked sessions (cron). Returns the number removed. */
	async pruneSessions(now: number): Promise<number> {
		const result = await this.d1
			.prepare('DELETE FROM sessions WHERE expires_at < ? OR revoked_at IS NOT NULL')
			.bind(now)
			.run()
		return result.meta.changes ?? 0
	}

	// ── Audit (append-only) ───────────────────────────────────────────────────

	/** Write a domain audit event. Diff/metadata stored verbatim (JSON-encoded). */
	async writeAuditEvent(input: AuditEventInput): Promise<void> {
		const id = uuidv7()
		await this.d1
			.prepare(`INSERT INTO audit_events
				(id, request_id, principal_id, principal_label, credential_id, app, action, resource_type, resource_id, diff, metadata)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
			.bind(
				id,
				input.requestId,
				input.principalId,
				input.principalLabel,
				input.credentialId ?? null,
				input.app,
				input.action,
				input.resourceType,
				input.resourceId ?? null,
				input.diff === undefined ? null : JSON.stringify(input.diff),
				input.metadata === undefined ? null : JSON.stringify(input.metadata),
			)
			.run()
	}

	async writeAuthLog(input: AuthLogInput): Promise<void> {
		await this.d1
			.prepare(`INSERT INTO auth_log
				(request_id, app, kind, principal_id, credential_id, decision, reason)
				VALUES (?, ?, ?, ?, ?, ?, ?)`)
			.bind(
				input.requestId,
				input.app,
				input.kind,
				input.principalId,
				input.credentialId ?? null,
				input.decision,
				input.reason ?? null,
			)
			.run()
	}

	// ── Audit reads (admin) ───────────────────────────────────────────────────

	async listAuditEvents(filter: {
		resourceType?: string
		resourceId?: string
		principalId?: string
		action?: string
		requestId?: string
		before?: string
		limit: number
	}): Promise<AuditEventRow[]> {
		const where: string[] = []
		const binds: (string | number)[] = []
		if (filter.resourceType) {
			where.push('resource_type = ?')
			binds.push(filter.resourceType)
		}
		if (filter.resourceId) {
			where.push('resource_id = ?')
			binds.push(filter.resourceId)
		}
		if (filter.principalId) {
			where.push('principal_id = ?')
			binds.push(filter.principalId)
		}
		if (filter.action) {
			where.push('action = ?')
			binds.push(filter.action)
		}
		if (filter.requestId) {
			where.push('request_id = ?')
			binds.push(filter.requestId)
		}
		if (filter.before) {
			// Cursor by UUIDv7 id (time-sortable) — keyset pagination, descending.
			where.push('id < ?')
			binds.push(filter.before)
		}
		const sql = `SELECT * FROM audit_events${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`
		binds.push(filter.limit)
		const { results } = await this.d1.prepare(sql).bind(...binds).all<AuditEventRow>()
		return results
	}

	async listAuthLog(filter: {
		principalId?: string
		requestId?: string
		decision?: 'allow' | 'deny'
		before?: number
		limit: number
	}): Promise<AuthLogRow[]> {
		const where: string[] = []
		const binds: (string | number)[] = []
		if (filter.principalId) {
			where.push('principal_id = ?')
			binds.push(filter.principalId)
		}
		if (filter.requestId) {
			where.push('request_id = ?')
			binds.push(filter.requestId)
		}
		if (filter.decision) {
			where.push('decision = ?')
			binds.push(filter.decision)
		}
		if (filter.before !== undefined) {
			// Cursor by rowid (time-correlated, monotonic) — keyset pagination.
			where.push('id < ?')
			binds.push(filter.before)
		}
		const sql = `SELECT * FROM auth_log${where.length ? ` WHERE ${where.join(' AND ')}` : ''} ORDER BY id DESC LIMIT ?`
		binds.push(filter.limit)
		const { results } = await this.d1.prepare(sql).bind(...binds).all<AuthLogRow>()
		return results
	}

	// ── Retention (cron) ──────────────────────────────────────────────────────

	/**
	 * Prune `auth_log` rows older than `olderThanSeconds` (unix seconds). The rowid
	 * is time-correlated, so pruning by `created_at` needs no extra index.
	 */
	async pruneAuthLog(olderThanSeconds: number): Promise<number> {
		const result = await this.d1
			.prepare('DELETE FROM auth_log WHERE created_at < ?')
			.bind(olderThanSeconds)
			.run()
		return result.meta.changes ?? 0
	}
}
