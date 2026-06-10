import type { IssueCapabilityInput, PermissionEntry } from '@propustka/core'
import type { ResolveOutcome } from '../auth'
import { resolveRequest } from '../auth'
import { issueCapability } from '../capabilities'
import { CfAccessClient, CfAccessError, type MintedServiceToken } from '../cfaccess'
import {
	type AuditEventRow,
	type AuthLogRow,
	type CapabilityTokenRow,
	type GrantRow,
	type GroupMappingRow,
	type PrincipalRow,
	principalStatus,
	type ProjectRow,
} from '../db'
import { booleanField, nullableStringField, numberField, parseJson, prop, stringField } from '../json'
import { computePermissions } from '../resolve'
import { isKnownRole, ROLES } from '../roles'
import type { Services } from '../services'
import { error, json, readJson } from './http'
import type {
	ApiKeyDto,
	AuditEventDto,
	AuthLogDto,
	CapabilityListItem,
	GrantDto,
	GroupMappingDto,
	IssuedCapabilityResponse,
	MeDto,
	PrincipalDetail,
	PrincipalListItem,
	ProjectDto,
	ProvisionApiKeyResponse,
	RoleDto,
	RotateApiKeyResponse,
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
	/** The original RPC-shaped authenticate input (forwarded for issueCapability). */
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

function toGrantDto(row: GrantRow): GrantDto {
	return {
		id: row.id,
		principalId: row.principal_id,
		roleKey: row.role_key,
		projectId: row.project_id,
		grantedBy: row.granted_by,
		expiresAt: row.expires_at,
		createdAt: row.created_at,
		dangling: !isKnownRole(row.role_key),
	}
}

function toGroupMappingDto(row: GroupMappingRow): GroupMappingDto {
	return {
		id: row.id,
		provider: row.provider,
		groupRef: row.group_ref,
		roleKey: row.role_key,
		projectId: row.project_id,
		createdAt: row.created_at,
		dangling: !isKnownRole(row.role_key),
	}
}

function toProjectDto(row: ProjectRow): ProjectDto {
	return { id: row.id, slug: row.slug, name: row.name, createdAt: row.created_at }
}

function toAuditEventDto(row: AuditEventRow): AuditEventDto {
	return {
		id: row.id,
		requestId: row.request_id,
		principalId: row.principal_id,
		principalLabel: row.principal_label,
		capabilityTokenId: row.capability_token_id,
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
		capabilityTokenId: row.capability_token_id,
		decision: row.decision,
		reason: row.reason,
		createdAt: row.created_at,
	}
}

function toCapabilityListItem(row: CapabilityTokenRow, grants: { action: string; resource: string }[]): CapabilityListItem {
	return {
		id: row.id,
		label: row.label,
		issuedBy: row.issued_by,
		expiresAt: row.expires_at,
		maxUses: row.max_uses,
		usedCount: row.used_count,
		revokedAt: row.revoked_at,
		createdAt: row.created_at,
		grants,
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
		grants: grants.map(toGrantDto),
		permissions,
	}
	return json(detail)
}

// Effective permissions for the admin detail view. For services and for the
// explicit-grant/bootstrap portion of users this is exact; group-derived
// permissions are only resolvable with the user's own live cookie, so they are
// shown via the grants list and the auth log, not synthesised here.
async function effectivePermissionsForAdmin(c: AdminContext, row: PrincipalRow): Promise<PermissionEntry[]> {
	const grants = await c.services.db.getActiveGrants(row.id)
	const isBootstrapAdmin = row.type === 'user' && row.email !== null && c.services.config.bootstrapAdmins.has(row.email)
	return computePermissions({ grants, groupMappings: [], isBootstrapAdmin })
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

export async function createGrant(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const principalId = stringField(body, 'principalId')
	const roleKey = stringField(body, 'roleKey')
	if (!principalId || !roleKey) {
		return error(400, 'principalId and roleKey required')
	}
	if (!isKnownRole(roleKey)) {
		return error(400, `unknown role: ${roleKey}`)
	}
	const projectId = nullableStringField(body, 'projectId') ?? null
	const expiresAt = numberField(body, 'expiresAt') ?? null
	const principal = await c.services.db.getPrincipalById(principalId)
	if (!principal) {
		return error(404, 'principal not found')
	}
	if (projectId != null) {
		const project = await c.services.db.getProjectById(projectId)
		if (!project) {
			return error(404, 'project not found')
		}
	}
	const grant = await c.services.db.createGrant({
		principalId,
		roleKey,
		projectId,
		grantedBy: c.admin.id,
		expiresAt,
	})
	await adminAudit(c, {
		action: 'iam.grant.create',
		resourceType: 'grant',
		resourceId: grant.id,
		metadata: { principalId, roleKey, projectId },
	})
	return json(toGrantDto(grant), { status: 201 })
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
		metadata: { principalId: grant.principal_id, roleKey: grant.role_key, projectId: grant.project_id },
	})
	return json({ ok: true })
}

// ── Projects ──────────────────────────────────────────────────────────────────

export async function listProjects(c: AdminContext): Promise<Response> {
	const rows = await c.services.db.listProjects()
	return json({ items: rows.map(toProjectDto) } satisfies { items: ProjectDto[] })
}

export async function createProject(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const slug = stringField(body, 'slug')
	const name = stringField(body, 'name')
	if (!slug || !name) {
		return error(400, 'slug and name required')
	}
	const project = await c.services.db.createProject({ slug, name })
	await adminAudit(c, {
		action: 'iam.project.create',
		resourceType: 'project',
		resourceId: project.id,
		metadata: { slug, name },
	})
	return json(toProjectDto(project), { status: 201 })
}

export async function updateProject(c: AdminContext, id: string): Promise<Response> {
	const body = await readJson(c.request)
	const name = stringField(body, 'name')
	if (!name) {
		return error(400, 'name required')
	}
	const updated = await c.services.db.updateProject(id, name)
	if (!updated) {
		return error(404, 'project not found')
	}
	await adminAudit(c, {
		action: 'iam.project.update',
		resourceType: 'project',
		resourceId: id,
		diff: { name: [null, name] },
	})
	return json(toProjectDto(updated))
}

// ── Group → role mappings ─────────────────────────────────────────────────────

export async function listGroupMappings(c: AdminContext): Promise<Response> {
	const rows = await c.services.db.listGroupMappings()
	return json({ items: rows.map(toGroupMappingDto) } satisfies { items: GroupMappingDto[] })
}

export async function createGroupMapping(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const provider = stringField(body, 'provider')
	const groupRef = stringField(body, 'groupRef')
	const roleKey = stringField(body, 'roleKey')
	if (!provider || !groupRef || !roleKey) {
		return error(400, 'provider, groupRef and roleKey required')
	}
	if (!isKnownRole(roleKey)) {
		return error(400, `unknown role: ${roleKey}`)
	}
	const projectId = nullableStringField(body, 'projectId') ?? null
	if (projectId != null) {
		const project = await c.services.db.getProjectById(projectId)
		if (!project) {
			return error(404, 'project not found')
		}
	}
	const mapping = await c.services.db.createGroupMapping({ provider, groupRef, roleKey, projectId })
	await adminAudit(c, {
		action: 'iam.groupmapping.create',
		resourceType: 'group_mapping',
		resourceId: mapping.id,
		metadata: { provider, groupRef, roleKey, projectId },
	})
	return json(toGroupMappingDto(mapping), { status: 201 })
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

// ── Roles (read-only) ─────────────────────────────────────────────────────────

export function listRoles(): Response {
	const items: RoleDto[] = Object.entries(ROLES).map(([key, role]) => ({
		key,
		name: role.name,
		...(role.description ? { description: role.description } : {}),
		permissions: role.permissions,
	}))
	return json({ items } satisfies { items: RoleDto[] })
}

// ── API keys (service tokens) ─────────────────────────────────────────────────

export async function listApiKeys(c: AdminContext): Promise<Response> {
	const principals = await c.services.db.listPrincipals({ type: 'service' })
	const items: ApiKeyDto[] = []
	for (const principal of principals) {
		const grants = await c.services.db.listGrants(principal.id)
		items.push({
			principalId: principal.id,
			label: principal.label,
			clientId: principal.external_id,
			status: principalStatus(principal),
			grants: grants.map(toGrantDto),
			createdAt: principal.created_at,
		})
	}
	return json({ items } satisfies { items: ApiKeyDto[] })
}

/**
 * Provision an API key: mint an Access service token, create the IAM principal +
 * grant, return the secret ONCE. No distributed transaction is available, so on a
 * failure after mint we attempt a best-effort rollback (delete the token); if that
 * also fails we write `iam.apikey.orphaned` so the orphan is never left silent.
 *
 * Service Auth policy inclusion (spec step 6) is option (b): not automated — the
 * response carries `policyInclusion: 'manual'`.
 */
export async function provisionApiKey(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const label = stringField(body, 'label')
	const type = stringField(body, 'type')
	const roleKey = stringField(body, 'roleKey')
	if (!label || type !== 'service' || !roleKey) {
		return error(400, 'label, type=service and roleKey required')
	}
	if (!isKnownRole(roleKey)) {
		return error(400, `unknown role: ${roleKey}`)
	}
	const projectId = nullableStringField(body, 'projectId') ?? null
	const expiresAt = numberField(body, 'expiresAt') ?? null
	if (projectId != null) {
		const project = await c.services.db.getProjectById(projectId)
		if (!project) {
			return error(404, 'project not found')
		}
	}

	const cf = new CfAccessClient(c.services.config.cfApiToken, c.services.config.cfAccountId)

	// 1. Mint the token in Access. If this fails, nothing was created — clean.
	let minted: MintedServiceToken
	try {
		minted = await cf.createServiceToken(label)
	} catch (err) {
		const message = err instanceof CfAccessError ? err.message : 'failed to mint service token'
		return error(502, message)
	}

	// 2..5: create IAM principal + grant + audit. On any failure, roll the token back.
	try {
		const principal = await c.services.db.createService(minted.clientId, label)
		const grant = await c.services.db.createGrant({
			principalId: principal.id,
			roleKey,
			projectId,
			grantedBy: c.admin.id,
			expiresAt,
		})
		await adminAudit(c, {
			action: 'iam.apikey.create',
			resourceType: 'principal',
			resourceId: principal.id,
			metadata: { tokenId: minted.id, label, roleKey, projectId },
		})
		await adminAudit(c, {
			action: 'iam.grant.create',
			resourceType: 'grant',
			resourceId: grant.id,
			metadata: { principalId: principal.id, roleKey, projectId },
		})

		const response: ProvisionApiKeyResponse = {
			principalId: principal.id,
			clientId: minted.clientId,
			clientSecret: minted.clientSecret,
			tokenId: minted.id,
			policyInclusion: 'manual',
		}
		return json(response, { status: 201 })
	} catch (err) {
		// Best-effort rollback: delete the orphaned Access token. If THAT fails too,
		// record it for manual cleanup so a minted token never sits without an IAM record.
		try {
			await cf.deleteServiceToken(minted.id)
		} catch {
			await adminAudit(c, {
				action: 'iam.apikey.orphaned',
				resourceType: 'principal',
				metadata: { tokenId: minted.id, clientId: minted.clientId, label },
			})
		}
		const message = err instanceof Error ? err.message : 'provisioning failed after mint'
		return error(500, message)
	}
}

/**
 * Revoke an API key: (1) delete the Access service token, (3) hard-delete grants,
 * (4) soft-disable the principal, (5) write `iam.apikey.revoke`. (Step 2 — removing
 * the token from the Service Auth policy — is the manual counterpart of provisioning
 * step 6; not automated in v1.) Revocation is immediate: service auth has no session,
 * each request is re-evaluated.
 *
 * The Access token id isn't stored on the principal (the schema has no column), so it
 * is resolved from the stored client_id (`external_id`) via the Access API. Token
 * deletion is best-effort — IAM cleanup proceeds even if Access already lost it.
 */
export async function revokeApiKey(c: AdminContext, principalId: string): Promise<Response> {
	const principal = await c.services.db.getPrincipalById(principalId)
	if (!principal || principal.type !== 'service') {
		return error(404, 'service principal not found')
	}

	// 1. Delete the Access service token (best-effort).
	let tokenDeleted = false
	if (principal.external_id !== null) {
		const cf = new CfAccessClient(c.services.config.cfApiToken, c.services.config.cfAccountId)
		try {
			const tokenId = await cf.findTokenIdByClientId(principal.external_id)
			if (tokenId) {
				await cf.deleteServiceToken(tokenId)
				tokenDeleted = true
			}
		} catch {
			// Surface as metadata; still complete the IAM-side revocation below.
		}
	}

	// 3. Hard-delete grants. 4. Soft-disable the principal (keep audit references).
	await c.services.db.deleteGrantsForPrincipal(principalId)
	await c.services.db.disablePrincipal(principalId)
	await adminAudit(c, {
		action: 'iam.apikey.revoke',
		resourceType: 'principal',
		resourceId: principalId,
		metadata: { clientId: principal.external_id, accessTokenDeleted: tokenDeleted },
	})
	return json({ ok: true, accessTokenDeleted: tokenDeleted })
}

/**
 * Rotate an API key's secret: token id and IAM principal unchanged. Resolves the
 * Access token id from the stored client_id, rotates via the Access API, returns the
 * new secret ONCE, writes `iam.apikey.rotate`.
 */
export async function rotateApiKey(c: AdminContext, principalId: string): Promise<Response> {
	const principal = await c.services.db.getPrincipalById(principalId)
	if (!principal || principal.type !== 'service' || principal.external_id === null) {
		return error(404, 'service principal not found')
	}
	const cf = new CfAccessClient(c.services.config.cfApiToken, c.services.config.cfAccountId)
	let rotated: MintedServiceToken
	try {
		const tokenId = await cf.findTokenIdByClientId(principal.external_id)
		if (!tokenId) {
			return error(404, 'Access service token not found for this principal')
		}
		rotated = await cf.rotateServiceToken(tokenId)
	} catch (err) {
		const message = err instanceof CfAccessError ? err.message : 'rotation failed'
		return error(502, message)
	}
	await adminAudit(c, {
		action: 'iam.apikey.rotate',
		resourceType: 'principal',
		resourceId: principalId,
		metadata: { tokenId: rotated.id, clientId: rotated.clientId },
	})
	const response: RotateApiKeyResponse = {
		principalId,
		clientId: rotated.clientId,
		clientSecret: rotated.clientSecret,
		tokenId: rotated.id,
	}
	return json(response)
}

// ── Capability tokens ─────────────────────────────────────────────────────────

export async function listCapabilities(c: AdminContext): Promise<Response> {
	const tokens = await c.services.db.listCapabilityTokens()
	const items: CapabilityListItem[] = []
	for (const token of tokens) {
		const grants = await c.services.db.getCapabilityGrants(token.id)
		items.push(toCapabilityListItem(token, grants.map((g) => ({ action: g.action, resource: g.resource }))))
	}
	return json({ items } satisfies { items: CapabilityListItem[] })
}

export async function createCapability(c: AdminContext): Promise<Response> {
	const body = await readJson(c.request)
	const grants = parseIssueGrants(prop(body, 'grants'))
	if (grants === undefined || grants.length === 0) {
		return error(400, 'grants required (each: { action, resource, projectId? })')
	}
	const label = stringField(body, 'label')
	const expiresAt = numberField(body, 'expiresAt')
	const maxUses = numberField(body, 'maxUses')

	// Issue with the ADMIN'S OWN forwarded credentials — the delegation rule applies
	// to admins like everyone else (admins typically hold `*`, so it passes).
	const issueInput: IssueCapabilityInput = {
		app: c.app,
		token: c.authInput.token,
		cookie: c.authInput.cookie,
		origin: c.authInput.origin,
		requestId: c.authInput.requestId,
		grants,
		...(label !== undefined ? { label } : {}),
		...(expiresAt !== undefined ? { expiresAt } : {}),
		...(maxUses !== undefined ? { maxUses } : {}),
	}

	const { result, auditLabel } = await issueCapability(c.services, issueInput, c.admin)
	if (!result.ok) {
		// Admin already gated; the only failure here is the delegation rule.
		return error(403, `not allowed: ${result.reason}`)
	}
	await adminAudit(c, {
		action: 'iam.capability.create',
		resourceType: 'capability',
		resourceId: result.id,
		metadata: { label: auditLabel ?? null, grants: grants.map((g) => ({ action: g.action, resource: g.resource })) },
	})
	const issued: IssuedCapabilityResponse = { id: result.id, token: result.token }
	return json(issued, { status: 201 })
}

/** Parse the `grants` array from an issue request; undefined when malformed. */
function parseIssueGrants(value: unknown): IssueCapabilityInput['grants'] | undefined {
	if (!Array.isArray(value)) {
		return undefined
	}
	const out: IssueCapabilityInput['grants'] = []
	for (const item of value) {
		const action = stringField(item, 'action')
		const resource = stringField(item, 'resource')
		if (!action || !resource) {
			return undefined
		}
		const projectId = nullableStringField(item, 'projectId')
		out.push({ action, resource, ...(projectId !== undefined ? { projectId } : {}) })
	}
	return out
}

export async function revokeCapability(c: AdminContext, id: string): Promise<Response> {
	const token = await c.services.db.getCapabilityTokenById(id)
	if (!token) {
		return error(404, 'capability not found')
	}
	await c.services.db.revokeCapabilityToken(id)
	await adminAudit(c, {
		action: 'iam.capability.revoke',
		resourceType: 'capability',
		resourceId: id,
		metadata: { label: token.label },
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
