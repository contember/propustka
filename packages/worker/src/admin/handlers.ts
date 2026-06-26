import type { AccessAppDecl, AccessRule, AppAccess, AppSchema, IssueKeyInput, KeyGrant, PermissionEntry, RoleDef } from '@propustka/core'
import { API_KEY_PREFIX, isActionAllowed } from '@propustka/core'
import type { ResolveOutcome } from '../auth'
import { resolveRequest } from '../auth'
import { CfAccessError } from '../cfaccess'
import {
	type AuditEventRow,
	type AuthLogRow,
	type CredentialGrantRow,
	type CredentialRow,
	type GrantRow,
	type GroupMappingRow,
	type PrincipalRow,
	principalStatus,
	type RoleRow,
} from '../db'
import { normalizeGroupRef } from '../identity'
import { issueKey } from '../issue'
import { arrayField, booleanField, nullableStringField, numberField, parseJson, prop, stringField } from '../json'
import { computePermissions } from '../resolve'
import { BUILTIN_ROLES, isKnownRole, makeRoleSource } from '../roles'
import { generateToken, hashToken } from '../secret'
import type { Services } from '../services'
import { error, json, readJson } from './http'
import { type AppAccessReadback, readAppAccess, reconcileAccess, ReconcileAccessError } from './reconcile-access'
import type {
	ApiKeyDto,
	AppAccessDto,
	AppDto,
	AppSchemaDto,
	AuditEventDto,
	AuthLogDto,
	GrantDto,
	GroupMappingDto,
	IssuedShareLinkResponse,
	MeDto,
	PolicyDto,
	PrincipalDetail,
	PrincipalListItem,
	ProvisionApiKeyResponse,
	RoleDto,
	RotateApiKeyResponse,
	ShareLinkListItem,
} from './types'

/**
 * Context every admin handler receives: the resolved admin caller (already gated
 * on `iam.admin` by the router), the request, parsed URL, and the verified app id
 * for audit labeling.
 */
export interface AdminContext {
	services: Services
	request: Request
	url: URL
	admin: { id: string; label: string; permissions: PermissionEntry[] }
	/** Verified app id from the admin's own forwarded token (aud-derived). */
	app: string
	/** The full resolve outcome, reused so handlers can forward the admin's credentials. */
	outcome: ResolveOutcome
	/** The original RPC-shaped authenticate input (forwarded for issueKey / share-link issue). */
	authInput: { token: string | null; cookie: string | null; origin: string | null; requestId: string }
	ctx: ExecutionContext
}

// ── DTO mappers ───────────────────────────────────────────────────────────────

function toPrincipalListItem(row: PrincipalRow): PrincipalListItem {
	return {
		id: row.id,
		type: row.type,
		label: row.label,
		email: row.email,
		externalId: row.external_id,
		status: principalStatus(row),
		createdAt: row.created_at,
	}
}

/** Parse a `roles` row's JSON permissions into a string array (fail-closed on junk). */
function rolePermissions(json: string): string[] {
	const parsed = parseJson(json)
	if (!Array.isArray(parsed)) {
		return []
	}
	return parsed.filter((p): p is string => typeof p === 'string')
}

/**
 * Loads (and memoizes) an app's role_key set on demand so DTO mappers can flag
 * dangling role grants without re-querying per row. A grant/mapping with `app = null`
 * (cross-app) is checked against the built-ins only — there is no per-app row set.
 */
class RoleKnownCache {
	private readonly perApp = new Map<string, Set<string>>()

	constructor(private readonly services: Services) {}

	private async appRoleKeys(app: string): Promise<Set<string>> {
		const cached = this.perApp.get(app)
		if (cached) {
			return cached
		}
		const rows = await this.services.db.listRoles(app)
		const keys = new Set(rows.map((r) => r.role_key))
		this.perApp.set(app, keys)
		return keys
	}

	/** True iff `roleKey` resolves for `app` — a built-in, or a row in the app's roles. */
	async isKnown(roleKey: string, app: string | null): Promise<boolean> {
		if (Object.hasOwn(BUILTIN_ROLES, roleKey)) {
			return true
		}
		if (app === null) {
			return false
		}
		return (await this.appRoleKeys(app)).has(roleKey)
	}
}

async function toGrantDto(row: GrantRow, roleCache: RoleKnownCache): Promise<GrantDto> {
	const dangling = row.role_key !== null && !(await roleCache.isKnown(row.role_key, row.app))
	return {
		id: row.id,
		principalId: row.principal_id,
		roleKey: row.role_key,
		permissions: row.permissions === null ? null : rolePermissions(row.permissions),
		scopeType: row.scope_type,
		scopeValue: row.scope_value,
		app: row.app,
		grantedBy: row.granted_by,
		expiresAt: row.expires_at,
		createdAt: row.created_at,
		dangling,
	}
}

async function toGroupMappingDto(row: GroupMappingRow, roleCache: RoleKnownCache): Promise<GroupMappingDto> {
	return {
		id: row.id,
		provider: row.provider,
		groupRef: row.group_ref,
		roleKey: row.role_key,
		scopeType: row.scope_type,
		scopeValue: row.scope_value,
		app: row.app,
		createdAt: row.created_at,
		dangling: !(await roleCache.isKnown(row.role_key, row.app)),
	}
}

/** Map a list of grant rows to DTOs sharing one role-known cache (one query per app). */
async function toGrantDtos(rows: GrantRow[], services: Services): Promise<GrantDto[]> {
	const cache = new RoleKnownCache(services)
	const out: GrantDto[] = []
	for (const row of rows) {
		out.push(await toGrantDto(row, cache))
	}
	return out
}

/** The set of app ids propustka serves (the value side of ACCESS_APPS). */
function knownApps(c: AdminContext): string[] {
	return [...new Set(Object.values(c.services.config.accessApps))]
}

/** Validate an admin-supplied `app`: null (all apps) or a configured ACCESS_APPS value. */
function appField(c: AdminContext, body: unknown): { ok: true; app: string | null } | { ok: false } {
	const app = nullableStringField(body, 'app') ?? null
	if (app !== null && !knownApps(c).includes(app)) {
		return { ok: false }
	}
	return { ok: true, app }
}

function toAuditEventDto(row: AuditEventRow): AuditEventDto {
	return {
		id: row.id,
		requestId: row.request_id,
		principalId: row.principal_id,
		principalLabel: row.principal_label,
		credentialId: row.credential_id,
		app: row.app,
		action: row.action,
		resourceType: row.resource_type,
		resourceId: row.resource_id,
		diff: row.diff === null ? null : parseJson(row.diff),
		metadata: row.metadata === null ? null : parseJson(row.metadata),
		createdAt: row.created_at,
	}
}

function toAuthLogDto(row: AuthLogRow): AuthLogDto {
	return {
		id: row.id,
		requestId: row.request_id,
		app: row.app,
		kind: row.kind,
		principalId: row.principal_id,
		credentialId: row.credential_id,
		decision: row.decision,
		reason: row.reason,
		createdAt: row.created_at,
	}
}

function toShareLinkListItem(row: CredentialRow, grants: CredentialGrantRow[]): ShareLinkListItem {
	return {
		id: row.id,
		label: row.label,
		issuedBy: row.issued_by,
		expiresAt: row.expires_at,
		revokedAt: row.revoked_at,
		createdAt: row.created_at,
		grants: grants.map((g) => ({
			action: g.action,
			scope: g.scope_type === null || g.scope_value === null ? null : { type: g.scope_type, value: g.scope_value },
		})),
	}
}

// Audit-event writes from admin actions happen on the request critical path so the
// admin sees a consistent state, but the write itself is small; we await it.
function adminAudit(
	c: AdminContext,
	event: { action: string; resourceType: string; resourceId?: string | null; diff?: unknown; metadata?: unknown },
): Promise<void> {
	return c.services.db.writeAuditEvent({
		requestId: c.authInput.requestId,
		principalId: c.admin.id,
		principalLabel: c.admin.label,
		app: c.app,
		action: event.action,
		resourceType: event.resourceType,
		resourceId: event.resourceId ?? null,
		diff: event.diff,
		metadata: event.metadata,
	})
}

// ── Me ────────────────────────────────────────────────────────────────────────

export function handleMe(c: AdminContext): Response {
	const me: MeDto = {
		id: c.admin.id,
		type: c.outcome.result.ok && c.outcome.result.principal.type === 'service' ? 'service' : 'user',
		label: c.admin.label,
		permissions: c.admin.permissions,
		groupsUnavailable: c.outcome.groupsUnavailable,
	}
	return json(me)
}

// ── Principals ────────────────────────────────────────────────────────────────

export async function listPrincipals(c: AdminContext): Promise<Response> {
	const typeParam = c.url.searchParams.get('type')
	const statusParam = c.url.searchParams.get('status')
	const q = c.url.searchParams.get('q') ?? undefined
	const type = typeParam === 'user' || typeParam === 'service' ? typeParam : undefined
	const rows = await c.services.db.listPrincipals({ type, ...(q ? { q } : {}) })
	const items = rows
		.map(toPrincipalListItem)
		.filter((item) => !statusParam || item.status === statusParam)
	return json({ items } satisfies { items: PrincipalListItem[] })
}

export async function getPrincipal(c: AdminContext, id: string): Promise<Response> {
	const row = await c.services.db.getPrincipalById(id)
	if (!row) {
		return error(404, 'principal not found')
	}
	const grants = await c.services.db.listGrants(id)

	// Effective permissions: resolve them the same way authenticate() does, but
	// without the live token (groups need a cookie we don't have here) — so this
	// reflects explicit grants + bootstrap; group-derived perms are login-time.
	const permissions = await effectivePermissionsForAdmin(c, row)

	const detail: PrincipalDetail = {
		...toPrincipalListItem(row),
		grants: await toGrantDtos(grants, c.services),
		permissions,
	}
	return json(detail)
}

/**
 * Effective permissions for the admin detail view. For services and for the
 * explicit-grant/bootstrap portion of users this is exact; group-derived
 * permissions are only resolvable with the user's own live cookie, so they are
 * shown via the grants list and the auth log, not synthesised here.
 *
 * The principal's active grants span all apps; we resolve over the ADMIN's own
 * verified app for role lookup (the cross-app `admin` built-in still resolves at any
 * app, and an app-scoped role grant for a different app simply resolves to nothing in
 * this view — exact effective resolution is per-app, done at authenticate() time).
 */
async function effectivePermissionsForAdmin(c: AdminContext, row: PrincipalRow): Promise<PermissionEntry[]> {
	const grants = await c.services.db.getActiveGrants(row.id)
	const isBootstrapAdmin = row.type === 'user' && row.email !== null && c.services.config.bootstrapAdmins.has(row.email)
	const app: string | null = c.app
	const appRoles: Record<string, RoleDef> = {}
	for (const dbRole of await c.services.db.listRoles(app)) {
		appRoles[dbRole.role_key] = dbRoleToDef(dbRole)
	}
	const roleSource = makeRoleSource(appRoles)
	return computePermissions({ app, grants, groupMappings: [], isBootstrapAdmin }, roleSource)
}

/** A `roles` row → core `RoleDef` for resolution. */
function dbRoleToDef(row: RoleRow): RoleDef {
	return {
		name: row.name,
		...(row.description !== null ? { description: row.description } : {}),
		permissions: rolePermissions(row.permissions),
	}
}

/** Load an app's DB roles into a role_key -> RoleDef map (empty for app=null). */
async function loadAppRoleMap(c: AdminContext, app: string | null): Promise<Record<string, RoleDef>> {
	const map: Record<string, RoleDef> = {}
	if (app !== null) {
		for (const row of await c.services.db.listRoles(app)) {
			map[row.role_key] = dbRoleToDef(row)
		}
	}
	return map
}

export async function invitePrincipal(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const email = stringField(body, 'email')
	if (!email) {
		return error(400, 'email required')
	}
	const existing = await c.services.db.getUserByEmail(email)
	if (existing) {
		return error(409, 'a user with this email already exists')
	}
	const principal = await c.services.db.inviteUser(email)
	await adminAudit(c, {
		action: 'iam.principal.invite',
		resourceType: 'principal',
		resourceId: principal.id,
		metadata: { email },
	})
	return json(toPrincipalListItem(principal), { status: 201 })
}

export async function deletePrincipal(c: AdminContext, id: string): Promise<Response> {
	const row = await c.services.db.getPrincipalById(id)
	if (!row) {
		return error(404, 'principal not found')
	}
	const status = principalStatus(row)
	if (status === 'invited') {
		// Unclaimed invite → cancel it (hard-delete; nothing references it yet).
		await c.services.db.deletePrincipal(id)
		await adminAudit(c, { action: 'iam.principal.invite_cancel', resourceType: 'principal', resourceId: id })
		return json({ ok: true })
	}
	// Claimed principal → soft-disable (preserve audit history & grant references).
	await c.services.db.disablePrincipal(id)
	await adminAudit(c, { action: 'iam.principal.disable', resourceType: 'principal', resourceId: id })
	return json({ ok: true })
}

export async function patchPrincipal(c: AdminContext, id: string): Promise<Response> {
	const body = await readJson(c.request)
	const disabled = booleanField(body, 'disabled')
	if (disabled === undefined) {
		return error(400, 'disabled (boolean) required')
	}
	const row = await c.services.db.getPrincipalById(id)
	if (!row) {
		return error(404, 'principal not found')
	}
	if (disabled) {
		await c.services.db.disablePrincipal(id)
		await adminAudit(c, { action: 'iam.principal.disable', resourceType: 'principal', resourceId: id })
	} else {
		await c.services.db.enablePrincipal(id)
		await adminAudit(c, { action: 'iam.principal.enable', resourceType: 'principal', resourceId: id })
	}
	const updated = await c.services.db.getPrincipalById(id)
	return json(updated ? toPrincipalListItem(updated) : { ok: true })
}

// ── Grants ────────────────────────────────────────────────────────────────────

/**
 * Validate the scope coordinate on a grant/key request: `scopeType`/`scopeValue` are
 * both-or-neither (both null = global). A half-set pair is a 400.
 */
function parseScope(body: unknown): { ok: true; scopeType: string | null; scopeValue: string | null } | { ok: false } {
	const scopeType = nullableStringField(body, 'scopeType') ?? null
	const scopeValue = nullableStringField(body, 'scopeValue') ?? null
	if ((scopeType === null) !== (scopeValue === null)) {
		return { ok: false }
	}
	return { ok: true, scopeType, scopeValue }
}

/**
 * Validate the role-or-inline choice for a grant/key against the app: EXACTLY one of
 * `roleKey` / `permissions`. A `roleKey` must be a known role for the app (built-in
 * `admin` OR a `roles` row). Inline `permissions` must each be a pattern allowed by
 * the app's action catalog (`app_actions`). Returns a normalized result or an error
 * message for a 400.
 */
async function parseRoleOrInline(
	c: AdminContext,
	body: unknown,
	app: string | null,
): Promise<{ ok: true; roleKey: string | null; permissions: string[] | null } | { ok: false; message: string }> {
	const roleKey = stringField(body, 'roleKey')
	const permissions = arrayField(body, 'permissions')
	if ((roleKey === undefined) === (permissions === undefined)) {
		return { ok: false, message: 'exactly one of roleKey or permissions is required' }
	}
	if (roleKey !== undefined) {
		if (!isKnownRole(roleKey, await loadAppRoleMap(c, app))) {
			return { ok: false, message: `unknown role: ${roleKey}` }
		}
		return { ok: true, roleKey, permissions: null }
	}
	// Inline permissions: validate each pattern against the app's action catalog.
	if (permissions === undefined || permissions.length === 0) {
		return { ok: false, message: 'permissions must be a non-empty array of action patterns' }
	}
	const catalog = app === null ? [] : await c.services.db.listActionCatalog(app)
	for (const pattern of permissions) {
		if (!isActionAllowed(pattern, catalog)) {
			return { ok: false, message: `unknown action pattern: ${pattern}` }
		}
	}
	return { ok: true, roleKey: null, permissions }
}

export async function createGrant(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const principalId = stringField(body, 'principalId')
	if (!principalId) {
		return error(400, 'principalId required')
	}
	const appResult = appField(c, body)
	if (!appResult.ok) {
		return error(400, 'unknown app')
	}
	const app = appResult.app
	const roleOrInline = await parseRoleOrInline(c, body, app)
	if (!roleOrInline.ok) {
		return error(400, roleOrInline.message)
	}
	const scope = parseScope(body)
	if (!scope.ok) {
		return error(400, 'scopeType and scopeValue must be both set or both omitted')
	}
	const expiresAt = numberField(body, 'expiresAt') ?? null
	const principal = await c.services.db.getPrincipalById(principalId)
	if (!principal) {
		return error(404, 'principal not found')
	}
	const grant = await c.services.db.createGrant({
		principalId,
		app,
		roleKey: roleOrInline.roleKey,
		permissions: roleOrInline.permissions,
		scopeType: scope.scopeType,
		scopeValue: scope.scopeValue,
		grantedBy: c.admin.id,
		expiresAt,
	})
	await adminAudit(c, {
		action: 'iam.grant.create',
		resourceType: 'grant',
		resourceId: grant.id,
		metadata: {
			principalId,
			roleKey: roleOrInline.roleKey,
			permissions: roleOrInline.permissions,
			scopeType: scope.scopeType,
			scopeValue: scope.scopeValue,
			app,
		},
	})
	const cache = new RoleKnownCache(c.services)
	return json(await toGrantDto(grant, cache), { status: 201 })
}

export async function deleteGrant(c: AdminContext, id: string): Promise<Response> {
	const grant = await c.services.db.getGrantById(id)
	if (!grant) {
		return error(404, 'grant not found')
	}
	await c.services.db.deleteGrant(id)
	await adminAudit(c, {
		action: 'iam.grant.revoke',
		resourceType: 'grant',
		resourceId: id,
		metadata: {
			principalId: grant.principal_id,
			roleKey: grant.role_key,
			scopeType: grant.scope_type,
			scopeValue: grant.scope_value,
		},
	})
	return json({ ok: true })
}

// ── Group → role mappings ─────────────────────────────────────────────────────

export async function listGroupMappings(c: AdminContext): Promise<Response> {
	const rows = await c.services.db.listGroupMappings()
	const cache = new RoleKnownCache(c.services)
	const items: GroupMappingDto[] = []
	for (const row of rows) {
		items.push(await toGroupMappingDto(row, cache))
	}
	return json({ items } satisfies { items: GroupMappingDto[] })
}

export async function createGroupMapping(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const provider = stringField(body, 'provider')
	const groupRef = stringField(body, 'groupRef')
	const roleKey = stringField(body, 'roleKey')
	if (!provider || !groupRef || !roleKey) {
		return error(400, 'provider, groupRef and roleKey required')
	}
	const appResult = appField(c, body)
	if (!appResult.ok) {
		return error(400, 'unknown app')
	}
	const app = appResult.app
	// A mapping is role-only. Validate the role is known for the app (built-in or a row).
	if (!isKnownRole(roleKey, await loadAppRoleMap(c, app))) {
		return error(400, `unknown role: ${roleKey}`)
	}
	// Validate the admin-supplied ref is in `<org>/<team>` shape (exactly one '/',
	// non-empty org and team after trimming), then store it NORMALIZED — lowercased +
	// trimmed via the same `normalizeGroupRef` resolution uses, and `provider` lowercased
	// — so the row matches exactly what `getMappingsForGroups('github', refs)` looks up at
	// resolution. Storing verbatim would silently confer zero permissions on a
	// case/whitespace mismatch.
	const slash = groupRef.indexOf('/')
	if (slash === -1 || groupRef.indexOf('/', slash + 1) !== -1) {
		return error(400, 'groupRef must be in <org>/<team> form')
	}
	const org = groupRef.slice(0, slash).trim()
	const team = groupRef.slice(slash + 1).trim()
	if (org === '' || team === '') {
		return error(400, 'groupRef must be in <org>/<team> form')
	}
	const normalizedGroupRef = normalizeGroupRef(org, team)
	const normalizedProvider = provider.trim().toLowerCase()
	const scope = parseScope(body)
	if (!scope.ok) {
		return error(400, 'scopeType and scopeValue must be both set or both omitted')
	}
	const mapping = await c.services.db.createGroupMapping({
		provider: normalizedProvider,
		groupRef: normalizedGroupRef,
		roleKey,
		app,
		scopeType: scope.scopeType,
		scopeValue: scope.scopeValue,
	})
	await adminAudit(c, {
		action: 'iam.groupmapping.create',
		resourceType: 'group_mapping',
		resourceId: mapping.id,
		metadata: {
			provider: normalizedProvider,
			groupRef: normalizedGroupRef,
			roleKey,
			scopeType: scope.scopeType,
			scopeValue: scope.scopeValue,
			app,
		},
	})
	const cache = new RoleKnownCache(c.services)
	return json(await toGroupMappingDto(mapping, cache), { status: 201 })
}

export async function deleteGroupMapping(c: AdminContext, id: string): Promise<Response> {
	const mapping = await c.services.db.getGroupMappingById(id)
	if (!mapping) {
		return error(404, 'group mapping not found')
	}
	await c.services.db.deleteGroupMapping(id)
	await adminAudit(c, {
		action: 'iam.groupmapping.delete',
		resourceType: 'group_mapping',
		resourceId: id,
		metadata: { provider: mapping.provider, groupRef: mapping.group_ref, roleKey: mapping.role_key },
	})
	return json({ ok: true })
}

// ── Apps (read-only; derived from ACCESS_APPS) ────────────────────────────────

/** The app ids a grant/mapping can be scoped to — the configured ACCESS_APPS values. */
export function listApps(c: AdminContext): Response {
	const items: AppDto[] = knownApps(c).map((id) => ({ id }))
	return json({ items } satisfies { items: AppDto[] })
}

// ── Roles (grantable role list for an app) ────────────────────────────────────

/**
 * The roles available to grant for an app: the built-ins (cross-app, e.g. `admin`)
 * plus the app's DB roles (origin 'app' + 'custom'). The app is taken from the `?app`
 * query param (an ACCESS_APPS value); without it, only built-ins are listed. Built-ins
 * win on a key collision so an app cannot shadow the cross-app `admin`.
 */
export async function listRoles(c: AdminContext): Promise<Response> {
	const items: RoleDto[] = []
	const appParam = c.url.searchParams.get('app')
	const app = appParam !== null && knownApps(c).includes(appParam) ? appParam : null
	const builtinKeys = new Set(Object.keys(BUILTIN_ROLES))
	if (app !== null) {
		for (const row of await c.services.db.listRoles(app)) {
			if (builtinKeys.has(row.role_key)) {
				continue // a built-in shadows any same-key DB row in the grantable list
			}
			items.push({
				key: row.role_key,
				name: row.name,
				...(row.description !== null ? { description: row.description } : {}),
				permissions: rolePermissions(row.permissions),
				origin: row.origin,
			})
		}
	}
	for (const [key, role] of Object.entries(BUILTIN_ROLES)) {
		items.push({
			key,
			name: role.name,
			...(role.description ? { description: role.description } : {}),
			permissions: role.permissions,
			origin: 'builtin',
		})
	}
	return json({ items } satisfies { items: RoleDto[] })
}

// ── App schema (reconciled vocabulary) ────────────────────────────────────────

/**
 * Validate that a value is a well-formed `AppSchema` (scopes/actions/roles arrays of
 * the right shape) and return it normalized, or an error message. Each role's
 * permission patterns are validated against the body's OWN action catalog via
 * `isActionAllowed` — an unknown action is a 400.
 */
function parseAppSchema(body: unknown): { ok: true; schema: AppSchema } | { ok: false; message: string } {
	const scopesRaw = prop(body, 'scopes')
	const actionsRaw = prop(body, 'actions')
	const rolesRaw = prop(body, 'roles')
	if (!Array.isArray(scopesRaw) || !Array.isArray(actionsRaw)) {
		return { ok: false, message: 'scopes and actions must be arrays' }
	}
	if (typeof rolesRaw !== 'object' || rolesRaw === null || Array.isArray(rolesRaw)) {
		return { ok: false, message: 'roles must be an object (role_key -> def)' }
	}

	const scopes: AppSchema['scopes'] = []
	for (const item of scopesRaw) {
		const type = stringField(item, 'type')
		if (type === undefined) {
			return { ok: false, message: 'each scope needs a string `type`' }
		}
		const label = stringField(item, 'label')
		scopes.push({ type, ...(label !== undefined ? { label } : {}) })
	}

	const actions: AppSchema['actions'] = []
	const catalog: string[] = []
	for (const item of actionsRaw) {
		const action = stringField(item, 'action')
		if (action === undefined) {
			return { ok: false, message: 'each action needs a string `action`' }
		}
		const description = stringField(item, 'description')
		actions.push({ action, ...(description !== undefined ? { description } : {}) })
		catalog.push(action)
	}

	const roles: AppSchema['roles'] = {}
	for (const [key, defRaw] of Object.entries(rolesRaw)) {
		const name = stringField(defRaw, 'name')
		const permissions = arrayField(defRaw, 'permissions')
		if (name === undefined || permissions === undefined) {
			return { ok: false, message: `role '${key}' needs a string name and a permissions array` }
		}
		for (const pattern of permissions) {
			if (!isActionAllowed(pattern, catalog)) {
				return { ok: false, message: `role '${key}' references unknown action: ${pattern}` }
			}
		}
		const description = stringField(defRaw, 'description')
		roles[key] = { name, permissions, ...(description !== undefined ? { description } : {}) }
	}

	return { ok: true, schema: { scopes, actions, roles } }
}

/**
 * Reconcile an app's declared vocabulary (idempotent): upsert its scopes/actions and
 * origin='app' roles, delete app-origin rows absent from the body, and NEVER touch
 * origin='custom' roles. Every role's patterns are validated against the body's own
 * action catalog. The `:app` path segment must be a configured ACCESS_APPS value.
 */
export async function putAppSchema(c: AdminContext, app: string): Promise<Response> {
	// No knownApps gate: an app's FIRST schema reconcile is how it registers its vocabulary (this
	// endpoint is admin-gated). Its aud is added to ACCESS_APPS separately, for runtime JWT validation.
	const body = await readJson(c.request)
	const parsed = parseAppSchema(body)
	if (!parsed.ok) {
		return error(400, parsed.message)
	}
	const { schema } = parsed
	await c.services.db.reconcileAppSchema({
		app,
		scopes: schema.scopes.map((s) => ({ scopeType: s.type, label: s.label ?? null })),
		actions: schema.actions.map((a) => ({ action: a.action, description: a.description ?? null })),
		roles: Object.entries(schema.roles).map(([roleKey, def]) => ({
			roleKey,
			name: def.name,
			description: def.description ?? null,
			permissions: def.permissions,
		})),
	})
	await adminAudit(c, {
		action: 'iam.app.schema.reconcile',
		resourceType: 'app',
		resourceId: app,
		metadata: {
			scopes: schema.scopes.length,
			actions: schema.actions.length,
			roles: Object.keys(schema.roles),
		},
	})
	return json(await readAppSchemaDto(c, app))
}

/** Read the app's scopes, actions, and origin='app' roles into a DTO (no auth gate). */
async function readAppSchemaDto(c: AdminContext, app: string): Promise<AppSchemaDto> {
	const scopeRows = await c.services.db.listAppScopes(app)
	const actionRows = await c.services.db.listAppActions(app)
	const roleRows = await c.services.db.listRolesByOrigin(app, 'app')
	const roles: Record<string, RoleDef> = {}
	for (const row of roleRows) {
		roles[row.role_key] = dbRoleToDef(row)
	}
	return {
		app,
		scopes: scopeRows.map((r) => ({ type: r.scope_type, ...(r.label !== null ? { label: r.label } : {}) })),
		actions: actionRows.map((r) => ({ action: r.action, ...(r.description !== null ? { description: r.description } : {}) })),
		roles,
	}
}

/** Return the app's scopes, actions, and origin='app' roles (the reconciled vocabulary). */
export async function getAppSchema(c: AdminContext, app: string): Promise<Response> {
	if (!knownApps(c).includes(app)) {
		return error(404, 'unknown app')
	}
	return json(await readAppSchemaDto(c, app))
}

// ── Access edge rules (reconciled into Cloudflare as reusable policies) ─────────

/** Validate one declared Access rule. */
function parseAccessRule(raw: unknown): { ok: true; rule: AccessRule } | { ok: false; message: string } {
	const kind = stringField(raw, 'kind')
	if (kind === undefined) {
		return { ok: false, message: 'each rule needs a string `kind`' }
	}
	if (kind === 'service-auth') {
		return { ok: true, rule: { kind: 'service-auth' } }
	}
	if (kind === 'public') {
		return { ok: true, rule: { kind: 'public' } }
	}
	if (kind === 'human') {
		// The human AUDIENCE is owned centrally by propustka (HUMAN_EMAIL_DOMAINS / HUMAN_EMAILS), not
		// by the app — a human rule declares only THAT a path is human-gated. Any per-app emailDomains
		// / emails are ignored (accepted for back-compat, never applied).
		return { ok: true, rule: { kind: 'human' } }
	}
	return { ok: false, message: `unknown rule kind: ${kind}` }
}

/**
 * Validate an `AppAccess` body: a non-empty `apps` array, each with a unique `key`, a `name`,
 * non-empty `destinations`, and a non-empty `rules` list of valid rules. Keys must be unique
 * because they distinguish the per-CF-app managed policy names.
 */
function parseAppAccess(body: unknown): { ok: true; access: AppAccess } | { ok: false; message: string } {
	const appsRaw = prop(body, 'apps')
	if (!Array.isArray(appsRaw) || appsRaw.length === 0) {
		return { ok: false, message: 'apps must be a non-empty array' }
	}
	const apps: AccessAppDecl[] = []
	const seenKeys = new Set<string>()
	for (const appRaw of appsRaw) {
		const key = stringField(appRaw, 'key')
		const name = stringField(appRaw, 'name')
		if (!key || !name) {
			return { ok: false, message: 'each app needs a non-empty string `key` and `name`' }
		}
		if (seenKeys.has(key)) {
			return { ok: false, message: `duplicate app key: ${key}` }
		}
		seenKeys.add(key)
		const destinations = arrayField(appRaw, 'destinations')
		if (destinations === undefined || destinations.length === 0) {
			return { ok: false, message: `app '${key}' needs a non-empty destinations array` }
		}
		const rulesRaw = prop(appRaw, 'rules')
		if (!Array.isArray(rulesRaw) || rulesRaw.length === 0) {
			return { ok: false, message: `app '${key}' needs a non-empty rules array` }
		}
		const rules: AccessRule[] = []
		for (const ruleRaw of rulesRaw) {
			const parsed = parseAccessRule(ruleRaw)
			if (!parsed.ok) {
				return { ok: false, message: `app '${key}': ${parsed.message}` }
			}
			rules.push(parsed.rule)
		}
		const sessionDuration = stringField(appRaw, 'sessionDuration')
		apps.push({ key, name, destinations, ...(sessionDuration !== undefined ? { sessionDuration } : {}), rules })
	}
	return { ok: true, access: { apps } }
}

/** Map the live readback to the admin DTO. */
function toAppAccessDto(readback: AppAccessReadback): AppAccessDto {
	return {
		app: readback.app,
		policies: readback.policies.map((p) => ({ key: p.key, kind: p.kind, name: p.name, decision: p.decision, appCount: p.appCount })),
	}
}

/**
 * Reconcile an app's declared Access edge rules into Cloudflare (idempotent). Creates/updates the
 * managed reusable policies (`px:<app>:…`) and repoints the CF apps' policy arrays; never touches
 * non-managed policies. Returns the live readback. An app's FIRST access reconcile registers it and
 * creates its CF Access app — no prior ACCESS_APPS entry required (this endpoint is admin-gated).
 */
export async function putAppAccess(c: AdminContext, app: string): Promise<Response> {
	const body = await readJson(c.request)
	const parsed = parseAppAccess(body)
	if (!parsed.ok) {
		return error(400, parsed.message)
	}
	let readback: AppAccessReadback
	try {
		readback = await reconcileAccess(c.services.cfAccess, app, parsed.access, c.services.config.human)
	} catch (err) {
		if (err instanceof CfAccessError) {
			return error(502, err.message)
		}
		const message = err instanceof ReconcileAccessError ? err.message : 'access reconcile failed'
		return error(500, message)
	}
	await adminAudit(c, {
		action: 'iam.app.access.reconcile',
		resourceType: 'app',
		resourceId: app,
		metadata: {
			cfApps: parsed.access.apps.map((a) => a.name),
			rules: parsed.access.apps.flatMap((a) => a.rules.map((r) => `${a.key}:${r.kind}`)),
		},
	})
	return json(toAppAccessDto(readback))
}

/** Read the reusable Access policies propustka manages for an app (live CF state). */
export async function getAppAccess(c: AdminContext, app: string): Promise<Response> {
	if (!knownApps(c).includes(app)) {
		return error(404, 'unknown app')
	}
	try {
		const readback = await readAppAccess(c.services.cfAccess, app)
		return json(toAppAccessDto(readback))
	} catch (err) {
		const message = err instanceof CfAccessError ? err.message : 'failed to read access rules'
		return error(502, message)
	}
}

// ── Policies (origin='custom' roles) ──────────────────────────────────────────

function toPolicyDto(row: RoleRow): PolicyDto {
	return {
		app: row.app,
		key: row.role_key,
		name: row.name,
		...(row.description !== null ? { description: row.description } : {}),
		permissions: rolePermissions(row.permissions),
		createdAt: row.created_at,
	}
}

/** List an app's custom policies (origin='custom' role rows). */
export async function listPolicies(c: AdminContext, app: string): Promise<Response> {
	if (!knownApps(c).includes(app)) {
		return error(404, 'unknown app')
	}
	const rows = await c.services.db.listRolesByOrigin(app, 'custom')
	return json({ items: rows.map(toPolicyDto) } satisfies { items: PolicyDto[] })
}

/**
 * Validate a policy body's action patterns against the app's catalog (`app_actions`),
 * returning normalized fields or an error message. Shared by create + update.
 */
async function parsePolicyBody(
	c: AdminContext,
	app: string,
	body: unknown,
	requireKey: boolean,
): Promise<{ ok: true; key: string | undefined; name: string; description: string | null; permissions: string[] } | { ok: false; message: string }> {
	const key = stringField(body, 'key')
	const name = stringField(body, 'name')
	const permissions = arrayField(body, 'permissions')
	if (requireKey && key === undefined) {
		return { ok: false, message: 'key required' }
	}
	if (name === undefined || permissions === undefined) {
		return { ok: false, message: 'name and permissions (array) required' }
	}
	if (permissions.length === 0) {
		return { ok: false, message: 'permissions must be a non-empty array of action patterns' }
	}
	// A custom policy must not collide with a built-in role key.
	if (key !== undefined && Object.hasOwn(BUILTIN_ROLES, key)) {
		return { ok: false, message: `'${key}' is a reserved built-in role key` }
	}
	const catalog = await c.services.db.listActionCatalog(app)
	for (const pattern of permissions) {
		if (!isActionAllowed(pattern, catalog)) {
			return { ok: false, message: `unknown action pattern: ${pattern}` }
		}
	}
	const description = stringField(body, 'description') ?? null
	return { ok: true, key, name, description, permissions }
}

/** Create a custom policy (origin='custom' role). Rejects a key that already exists. */
export async function createPolicy(c: AdminContext, app: string): Promise<Response> {
	if (!knownApps(c).includes(app)) {
		return error(404, 'unknown app')
	}
	const body = await readJson(c.request)
	const parsed = await parsePolicyBody(c, app, body, true)
	if (!parsed.ok) {
		return error(400, parsed.message)
	}
	const key = parsed.key
	if (key === undefined) {
		return error(400, 'key required')
	}
	const existing = await c.services.db.getRole(app, key)
	if (existing) {
		return error(409, `a role with key '${key}' already exists`)
	}
	const row = await c.services.db.upsertRole({
		app,
		roleKey: key,
		name: parsed.name,
		description: parsed.description,
		permissions: parsed.permissions,
		origin: 'custom',
	})
	await adminAudit(c, {
		action: 'iam.policy.create',
		resourceType: 'policy',
		resourceId: `${app}/${key}`,
		metadata: { app, key, permissions: parsed.permissions },
	})
	return json(toPolicyDto(row), { status: 201 })
}

/** Update a custom policy. Rejects if the key is missing or is an origin='app' role. */
export async function updatePolicy(c: AdminContext, app: string, key: string): Promise<Response> {
	if (!knownApps(c).includes(app)) {
		return error(404, 'unknown app')
	}
	const existing = await c.services.db.getRole(app, key)
	if (!existing || existing.origin !== 'custom') {
		return error(404, 'custom policy not found')
	}
	const body = await readJson(c.request)
	const parsed = await parsePolicyBody(c, app, body, false)
	if (!parsed.ok) {
		return error(400, parsed.message)
	}
	const row = await c.services.db.upsertRole({
		app,
		roleKey: key,
		name: parsed.name,
		description: parsed.description,
		permissions: parsed.permissions,
		origin: 'custom',
	})
	await adminAudit(c, {
		action: 'iam.policy.update',
		resourceType: 'policy',
		resourceId: `${app}/${key}`,
		metadata: { app, key, permissions: parsed.permissions },
	})
	return json(toPolicyDto(row))
}

/** Delete a custom policy. Refuses to delete an origin='app' (reconciled) role. */
export async function deletePolicy(c: AdminContext, app: string, key: string): Promise<Response> {
	if (!knownApps(c).includes(app)) {
		return error(404, 'unknown app')
	}
	const existing = await c.services.db.getRole(app, key)
	if (!existing || existing.origin !== 'custom') {
		return error(404, 'custom policy not found')
	}
	await c.services.db.deleteRole(app, key)
	await adminAudit(c, {
		action: 'iam.policy.delete',
		resourceType: 'policy',
		resourceId: `${app}/${key}`,
		metadata: { app, key },
	})
	return json({ ok: true })
}

// ── API keys (native service credentials) ─────────────────────────────────────

export async function listApiKeys(c: AdminContext): Promise<Response> {
	const principals = await c.services.db.listPrincipals({ type: 'service' })
	const cache = new RoleKnownCache(c.services)
	const items: ApiKeyDto[] = []
	for (const principal of principals) {
		const grants = await c.services.db.listGrants(principal.id)
		const grantDtos: GrantDto[] = []
		for (const g of grants) {
			grantDtos.push(await toGrantDto(g, cache))
		}
		items.push({
			principalId: principal.id,
			label: principal.label,
			status: principalStatus(principal),
			grants: grantDtos,
			createdAt: principal.created_at,
		})
	}
	return json({ items } satisfies { items: ApiKeyDto[] })
}

/**
 * Provision an API key: create a native service principal + grant and mint a `px_`
 * credential bound to it — resolved by the propustka-native path (`mintFromKey`), no
 * Cloudflare Access in front. The plaintext `px_` token is returned ONCE.
 *
 * There is no distributed transaction; the writes are local D1 (principal → grant →
 * credential). A failure partway leaves an orphan principal at worst — harmless (it
 * holds no live credential) and revocable from this page.
 */
export async function provisionApiKey(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const label = stringField(body, 'label')
	const type = stringField(body, 'type')
	if (!label || type !== 'service') {
		return error(400, 'label and type=service required')
	}
	const appResult = appField(c, body)
	if (!appResult.ok) {
		return error(400, 'unknown app')
	}
	const app = appResult.app
	const roleOrInline = await parseRoleOrInline(c, body, app)
	if (!roleOrInline.ok) {
		return error(400, roleOrInline.message)
	}
	const scope = parseScope(body)
	if (!scope.ok) {
		return error(400, 'scopeType and scopeValue must be both set or both omitted')
	}
	const expiresAt = numberField(body, 'expiresAt') ?? null
	const nowSeconds = Math.floor(Date.now() / 1000)
	if (expiresAt !== null && expiresAt <= nowSeconds) {
		return error(400, 'expiresAt must be in the future')
	}

	// Create the native service principal (external_id NULL — resolved by its `px_` key, not by a
	// CF client_id) + its grant, then mint the bound credential. Shown once.
	const principal = await c.services.db.createService(label)
	const grant = await c.services.db.createGrant({
		principalId: principal.id,
		app,
		roleKey: roleOrInline.roleKey,
		permissions: roleOrInline.permissions,
		scopeType: scope.scopeType,
		scopeValue: scope.scopeValue,
		grantedBy: c.admin.id,
		expiresAt,
	})
	const apiKey = `${API_KEY_PREFIX}${generateToken()}`
	await c.services.db.createCredential({
		tokenHash: await hashToken(apiKey),
		label,
		principalId: principal.id,
		issuedBy: c.admin.id,
		expiresAt,
		grants: [],
	})
	await adminAudit(c, {
		action: 'iam.apikey.create',
		resourceType: 'principal',
		resourceId: principal.id,
		metadata: { label, roleKey: roleOrInline.roleKey, permissions: roleOrInline.permissions, app },
	})
	await adminAudit(c, {
		action: 'iam.grant.create',
		resourceType: 'grant',
		resourceId: grant.id,
		metadata: {
			principalId: principal.id,
			roleKey: roleOrInline.roleKey,
			permissions: roleOrInline.permissions,
			scopeType: scope.scopeType,
			scopeValue: scope.scopeValue,
			app,
		},
	})

	const response: ProvisionApiKeyResponse = { principalId: principal.id, apiKey }
	return json(response, { status: 201 })
}

/**
 * Revoke an API key: hard-delete its grants, soft-disable the service principal, and
 * revoke its `px_` credentials so they stop minting immediately. Revocation is
 * effective at once — `mintFromKey` re-resolves the credential on every mint.
 */
export async function revokeApiKey(c: AdminContext, principalId: string): Promise<Response> {
	const principal = await c.services.db.getPrincipalById(principalId)
	if (!principal || principal.type !== 'service') {
		return error(404, 'service principal not found')
	}

	await c.services.db.deleteGrantsForPrincipal(principalId)
	await c.services.db.disablePrincipal(principalId)
	await c.services.db.revokeCredentialsForPrincipal(principalId)
	await adminAudit(c, {
		action: 'iam.apikey.revoke',
		resourceType: 'principal',
		resourceId: principalId,
		metadata: { label: principal.label },
	})
	return json({ ok: true })
}

/**
 * Rotate an API key: principal and grants unchanged. Revoke the principal's old `px_`
 * credentials and mint a fresh one, returned ONCE. Effective immediately.
 */
export async function rotateApiKey(c: AdminContext, principalId: string): Promise<Response> {
	const principal = await c.services.db.getPrincipalById(principalId)
	if (!principal || principal.type !== 'service') {
		return error(404, 'service principal not found')
	}
	await c.services.db.revokeCredentialsForPrincipal(principalId)
	const apiKey = `${API_KEY_PREFIX}${generateToken()}`
	await c.services.db.createCredential({
		tokenHash: await hashToken(apiKey),
		label: principal.label,
		principalId,
		issuedBy: c.admin.id,
		grants: [],
	})
	await adminAudit(c, {
		action: 'iam.apikey.rotate',
		resourceType: 'principal',
		resourceId: principalId,
		metadata: { label: principal.label },
	})
	const response: RotateApiKeyResponse = { principalId, apiKey }
	return json(response)
}

// ── Share links (anonymous credentials) ─────────────────────────────────────────

export async function listShareLinks(c: AdminContext): Promise<Response> {
	const creds = await c.services.db.listAnonymousCredentials()
	const items: ShareLinkListItem[] = []
	for (const cred of creds) {
		const grants = await c.services.db.getCredentialGrants(cred.id)
		items.push(toShareLinkListItem(cred, grants))
	}
	return json({ items } satisfies { items: ShareLinkListItem[] })
}

export async function createShareLink(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const grants = parseShareLinkGrants(prop(body, 'grants'))
	if (grants === undefined || grants.length === 0) {
		return error(400, 'grants required (each: { action, scope? })')
	}
	const label = stringField(body, 'label')
	const expiresAt = numberField(body, 'expiresAt')

	// Issue an anonymous credential with the ADMIN'S OWN forwarded credentials as issuer — the
	// delegation rule applies to admins like everyone else (admins typically hold `*`, so it passes).
	// The issuer is the resolved admin (`c.admin`) passed directly to `issueKey`, so `credential` is
	// unused here (the RPC entrypoint resolves it; this admin path already has the caller).
	const issueInput: IssueKeyInput = {
		app: c.app,
		credential: null,
		requestId: c.authInput.requestId,
		permissions: grants,
		...(label !== undefined ? { label } : {}),
		...(expiresAt !== undefined ? { expiresAt } : {}),
	}

	const { result, auditLabel } = await issueKey(c.services, issueInput, c.admin, c.app)
	if (!result.ok) {
		// Admin already gated; the only failure here is the delegation rule.
		return error(403, `not allowed: ${result.reason}`)
	}
	await adminAudit(c, {
		action: 'iam.credential.create',
		resourceType: 'credential',
		resourceId: result.id,
		metadata: { label: auditLabel ?? null, grants },
	})
	const issued: IssuedShareLinkResponse = { id: result.id, token: result.token }
	return json(issued, { status: 201 })
}

/**
 * Parse the `grants` array from a share-link issue request; undefined when malformed. Each grant is
 * an `action` + an optional `scope` ({ type, value }) — the credential's frozen inline grant, matched
 * by `permits` at use time. A `scope` present but not a well-formed coordinate fails the whole parse
 * (undefined → 400) rather than silently dropping it.
 */
function parseShareLinkGrants(value: unknown): KeyGrant[] | undefined {
	if (!Array.isArray(value)) {
		return undefined
	}
	const out: KeyGrant[] = []
	for (const item of value) {
		const action = stringField(item, 'action')
		if (!action) {
			return undefined
		}
		const scopeRaw = prop(item, 'scope')
		if (scopeRaw === undefined || scopeRaw === null) {
			out.push({ action, scope: null })
			continue
		}
		const type = stringField(scopeRaw, 'type')
		const scopeValue = stringField(scopeRaw, 'value')
		if (type === undefined || scopeValue === undefined) {
			return undefined
		}
		out.push({ action, scope: { type, value: scopeValue } })
	}
	return out
}

export async function revokeShareLink(c: AdminContext, id: string): Promise<Response> {
	// Only anonymous credentials are share links; a principal-bound key is managed on the api-keys
	// page, so it reads as not-found here.
	const cred = await c.services.db.getCredentialById(id)
	if (!cred || cred.principal_id !== null) {
		return error(404, 'share link not found')
	}
	await c.services.db.revokeCredential(id)
	await adminAudit(c, {
		action: 'iam.credential.revoke',
		resourceType: 'credential',
		resourceId: id,
		metadata: { label: cred.label },
	})
	return json({ ok: true })
}

// ── Audit & auth log reads ────────────────────────────────────────────────────

const DEFAULT_LIMIT = 50
const MAX_LIMIT = 200

function parseLimit(url: URL): number {
	const raw = url.searchParams.get('limit')
	if (!raw) {
		return DEFAULT_LIMIT
	}
	const n = Number.parseInt(raw, 10)
	if (!Number.isFinite(n) || n <= 0) {
		return DEFAULT_LIMIT
	}
	return Math.min(n, MAX_LIMIT)
}

export async function listAudit(c: AdminContext): Promise<Response> {
	const p = c.url.searchParams
	const limit = parseLimit(c.url)
	const rows = await c.services.db.listAuditEvents({
		...(p.get('resourceType') ? { resourceType: p.get('resourceType')! } : {}),
		...(p.get('resourceId') ? { resourceId: p.get('resourceId')! } : {}),
		...(p.get('principalId') ? { principalId: p.get('principalId')! } : {}),
		...(p.get('action') ? { action: p.get('action')! } : {}),
		...(p.get('requestId') ? { requestId: p.get('requestId')! } : {}),
		...(p.get('before') ? { before: p.get('before')! } : {}),
		limit,
	})
	const items = rows.map(toAuditEventDto)
	const last = items.at(-1)
	const nextCursor = items.length === limit && last ? last.id : null
	return json({ items, nextCursor } satisfies { items: AuditEventDto[]; nextCursor: string | null })
}

export async function listAuthLog(c: AdminContext): Promise<Response> {
	const p = c.url.searchParams
	const limit = parseLimit(c.url)
	const decisionParam = p.get('decision')
	const decision = decisionParam === 'allow' || decisionParam === 'deny' ? decisionParam : undefined
	const beforeRaw = p.get('before')
	const before = beforeRaw ? Number.parseInt(beforeRaw, 10) : undefined
	const rows = await c.services.db.listAuthLog({
		...(p.get('principalId') ? { principalId: p.get('principalId')! } : {}),
		...(p.get('requestId') ? { requestId: p.get('requestId')! } : {}),
		...(decision ? { decision } : {}),
		...(before !== undefined && Number.isFinite(before) ? { before } : {}),
		limit,
	})
	const items = rows.map(toAuthLogDto)
	const last = items.at(-1)
	const nextCursor = items.length === limit && last ? String(last.id) : null
	return json({ items, nextCursor } satisfies { items: AuthLogDto[]; nextCursor: string | null })
}

// Re-export for the router so resolveRequest is reachable through one import site.
export { resolveRequest }
