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

export interface ProjectRow {
	id: string
	slug: string
	name: string
	created_at: number
}

export interface GrantRow {
	id: string
	principal_id: string
	role_key: string
	project_id: string | null
	/** App id (ACCESS_APPS value) this grant applies to; NULL = all apps (cross-app). */
	app: string | null
	granted_by: string | null
	expires_at: number | null
	created_at: number
}

export interface GroupMappingRow {
	id: string
	provider: string
	group_ref: string
	role_key: string
	project_id: string | null
	/** App id this mapping applies to; NULL = all apps. */
	app: string | null
	created_at: number
}

export interface AuditEventRow {
	id: string
	request_id: string
	principal_id: string | null
	principal_label: string
	capability_token_id: string | null
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
	kind: 'authenticate' | 'redeem'
	principal_id: string | null
	capability_token_id: string | null
	decision: 'allow' | 'deny'
	reason: string | null
	created_at: number
}

export interface CapabilityTokenRow {
	id: string
	token_hash: string
	label: string | null
	issued_by: string | null
	expires_at: number | null
	max_uses: number | null
	used_count: number
	revoked_at: number | null
	created_at: number
}

export interface CapabilityGrantRow {
	token_id: string
	action: string
	resource: string
}

/** Derived principal status — invited (unclaimed) → active → disabled. */
export type PrincipalStatus = 'invited' | 'active' | 'disabled'

export function principalStatus(row: PrincipalRow): PrincipalStatus {
	if (row.disabled_at !== null) {
		return 'disabled'
	}
	if (row.external_id === null) {
		return 'invited'
	}
	return 'active'
}

// Inputs that audit/auth-log writes accept (the Worker stamps ids/timestamps).
export interface AuditEventInput {
	requestId: string
	principalId: string | null
	principalLabel: string
	capabilityTokenId?: string | null
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
	kind: 'authenticate' | 'redeem'
	principalId: string | null
	capabilityTokenId?: string | null
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
 * projects, capabilities (redeem/issue), and the two write-only audit tables.
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

	/** Create a service principal up-front (provisioning). `external_id` = client_id. */
	async createService(clientId: string, label: string): Promise<PrincipalRow> {
		const id = uuidv7()
		return firstRow<PrincipalRow>(
			this.d1
				.prepare(`INSERT INTO principals (id, type, external_id, email, label)
					VALUES (?, 'service', ?, NULL, ?) RETURNING *`)
				.bind(id, clientId, label),
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

	async createGrant(input: {
		principalId: string
		roleKey: string
		projectId?: string | null
		app?: string | null
		grantedBy?: string | null
		expiresAt?: number | null
	}): Promise<GrantRow> {
		const id = uuidv7()
		return firstRow<GrantRow>(
			this.d1
				.prepare(`INSERT INTO grants (id, principal_id, role_key, project_id, app, granted_by, expires_at)
					VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING *`)
				.bind(
					id,
					input.principalId,
					input.roleKey,
					input.projectId ?? null,
					input.app ?? null,
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
		projectId?: string | null
		app?: string | null
	}): Promise<GroupMappingRow> {
		const id = uuidv7()
		return firstRow<GroupMappingRow>(
			this.d1
				.prepare(`INSERT INTO group_role_mappings (id, provider, group_ref, role_key, project_id, app)
					VALUES (?, ?, ?, ?, ?, ?) RETURNING *`)
				.bind(id, input.provider, input.groupRef, input.roleKey, input.projectId ?? null, input.app ?? null),
		)
	}

	async getGroupMappingById(id: string): Promise<GroupMappingRow | null> {
		return this.d1.prepare('SELECT * FROM group_role_mappings WHERE id = ?').bind(id).first<GroupMappingRow>()
	}

	async deleteGroupMapping(id: string): Promise<boolean> {
		const result = await this.d1.prepare('DELETE FROM group_role_mappings WHERE id = ?').bind(id).run()
		return (result.meta.changes ?? 0) > 0
	}

	// ── Projects ──────────────────────────────────────────────────────────────

	async listProjects(): Promise<ProjectRow[]> {
		const { results } = await this.d1.prepare('SELECT * FROM projects ORDER BY created_at DESC').all<ProjectRow>()
		return results
	}

	async getProjectById(id: string): Promise<ProjectRow | null> {
		return this.d1.prepare('SELECT * FROM projects WHERE id = ?').bind(id).first<ProjectRow>()
	}

	async createProject(input: { slug: string; name: string }): Promise<ProjectRow> {
		const id = uuidv7()
		return firstRow<ProjectRow>(
			this.d1
				.prepare('INSERT INTO projects (id, slug, name) VALUES (?, ?, ?) RETURNING *')
				.bind(id, input.slug, input.name),
		)
	}

	async updateProject(id: string, name: string): Promise<ProjectRow | null> {
		return this.d1
			.prepare('UPDATE projects SET name = ? WHERE id = ? RETURNING *')
			.bind(name, id)
			.first<ProjectRow>()
	}

	// ── Capability tokens ─────────────────────────────────────────────────────

	/**
	 * Atomic redeem: validate + increment `used_count` in a single statement to
	 * avoid races. Zero rows → caller classifies via `getCapabilityTokenByHash`.
	 */
	async redeemCapabilityToken(tokenHash: string): Promise<{ id: string; label: string | null } | null> {
		return this.d1
			.prepare(`UPDATE capability_tokens SET used_count = used_count + 1
				WHERE token_hash = ?
					AND revoked_at IS NULL
					AND (expires_at IS NULL OR expires_at > unixepoch())
					AND (max_uses IS NULL OR used_count < max_uses)
				RETURNING id, label`)
			.bind(tokenHash)
			.first<{ id: string; label: string | null }>()
	}

	/** Follow-up classification lookup after a zero-row redeem. */
	async getCapabilityTokenByHash(tokenHash: string): Promise<CapabilityTokenRow | null> {
		return this.d1.prepare('SELECT * FROM capability_tokens WHERE token_hash = ?').bind(tokenHash).first<CapabilityTokenRow>()
	}

	async getCapabilityTokenById(id: string): Promise<CapabilityTokenRow | null> {
		return this.d1.prepare('SELECT * FROM capability_tokens WHERE id = ?').bind(id).first<CapabilityTokenRow>()
	}

	async getCapabilityGrants(tokenId: string): Promise<CapabilityGrantRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM capability_grants WHERE token_id = ?')
			.bind(tokenId)
			.all<CapabilityGrantRow>()
		return results
	}

	async listCapabilityTokens(): Promise<CapabilityTokenRow[]> {
		const { results } = await this.d1
			.prepare('SELECT * FROM capability_tokens ORDER BY created_at DESC')
			.all<CapabilityTokenRow>()
		return results
	}

	/** Insert the token + its grant rows. Only the hash is stored, never plaintext. */
	async createCapabilityToken(input: {
		tokenHash: string
		label?: string | null
		issuedBy: string
		expiresAt?: number | null
		maxUses?: number | null
		grants: { action: string; resource: string }[]
	}): Promise<string> {
		const id = uuidv7()
		const statements: D1PreparedStatement[] = [
			this.d1
				.prepare(`INSERT INTO capability_tokens (id, token_hash, label, issued_by, expires_at, max_uses)
					VALUES (?, ?, ?, ?, ?, ?)`)
				.bind(id, input.tokenHash, input.label ?? null, input.issuedBy, input.expiresAt ?? null, input.maxUses ?? null),
		]
		for (const grant of input.grants) {
			statements.push(
				this.d1
					.prepare('INSERT INTO capability_grants (token_id, action, resource) VALUES (?, ?, ?)')
					.bind(id, grant.action, grant.resource),
			)
		}
		await this.d1.batch(statements)
		return id
	}

	async revokeCapabilityToken(id: string): Promise<boolean> {
		const result = await this.d1
			.prepare('UPDATE capability_tokens SET revoked_at = unixepoch() WHERE id = ? AND revoked_at IS NULL')
			.bind(id)
			.run()
		return (result.meta.changes ?? 0) > 0
	}

	// ── Audit (append-only) ───────────────────────────────────────────────────

	/** Write a domain audit event. Diff/metadata stored verbatim (JSON-encoded). */
	async writeAuditEvent(input: AuditEventInput): Promise<void> {
		const id = uuidv7()
		await this.d1
			.prepare(`INSERT INTO audit_events
				(id, request_id, principal_id, principal_label, capability_token_id, app, action, resource_type, resource_id, diff, metadata)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
			.bind(
				id,
				input.requestId,
				input.principalId,
				input.principalLabel,
				input.capabilityTokenId ?? null,
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
				(request_id, app, kind, principal_id, capability_token_id, decision, reason)
				VALUES (?, ?, ?, ?, ?, ?, ?)`)
			.bind(
				input.requestId,
				input.app,
				input.kind,
				input.principalId,
				input.capabilityTokenId ?? null,
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
