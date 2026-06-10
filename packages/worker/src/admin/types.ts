// @propustka/worker/admin — admin REST request/response DTOs.
//
// Consumed type-only by @propustka/admin-ui (the opice dashboard pattern: end-to-end
// typed, no codegen). Reuses @propustka/core types where they fit. Keep these clean
// and complete — they ARE the admin API contract.

import type { PermissionEntry, PermissionSource, PrincipalType } from '@propustka/core'

// ── Common wrappers ───────────────────────────────────────────────────────────

/** A plain list response. */
export interface ListResponse<T> {
	items: T[]
}

/**
 * A cursor-paginated list. `nextCursor` is the opaque cursor to pass as `before`
 * for the next page; null when there are no more rows.
 */
export interface CursorList<T> {
	items: T[]
	nextCursor: string | null
}

// ── Principals ────────────────────────────────────────────────────────────────

/** Derived principal status — invited (unclaimed) → active → disabled. */
export type PrincipalStatus = 'invited' | 'active' | 'disabled'

export interface PrincipalListItem {
	id: string
	type: PrincipalType
	label: string
	email: string | null
	externalId: string | null
	status: PrincipalStatus
	createdAt: number
}

export interface GrantDto {
	id: string
	principalId: string
	roleKey: string
	projectId: string | null
	grantedBy: string | null
	expiresAt: number | null
	createdAt: number
	/** True when `roleKey` is no longer in the code role registry (resolves to zero perms). */
	dangling: boolean
}

export interface PrincipalDetail extends PrincipalListItem {
	grants: GrantDto[]
	/** Effective permissions with `source` (grant / bootstrap / group:<ref>). */
	permissions: PermissionEntry[]
}

export interface InviteRequest {
	email: string
}

export interface UpdatePrincipalRequest {
	disabled: boolean
}

// ── Grants ────────────────────────────────────────────────────────────────────

export interface CreateGrantRequest {
	principalId: string
	roleKey: string
	/** null / omitted = global. */
	projectId?: string | null
	expiresAt?: number | null
}

// ── Projects ──────────────────────────────────────────────────────────────────

export interface ProjectDto {
	id: string
	slug: string
	name: string
	createdAt: number
}

export interface CreateProjectRequest {
	slug: string
	name: string
}

export interface UpdateProjectRequest {
	name: string
}

// ── Group → role mappings ─────────────────────────────────────────────────────

export interface GroupMappingDto {
	id: string
	provider: string
	groupRef: string
	roleKey: string
	projectId: string | null
	createdAt: number
	/** True when `roleKey` is no longer in the code role registry. */
	dangling: boolean
}

export interface CreateGroupMappingRequest {
	provider: string
	groupRef: string
	roleKey: string
	projectId?: string | null
}

// ── Roles (read-only; live in code) ───────────────────────────────────────────

export interface RoleDto {
	key: string
	name: string
	description?: string
	permissions: string[]
}

// ── API keys (service tokens) ─────────────────────────────────────────────────

/** Metadata view of a service-principal API key (the secret is never returned here). */
export interface ApiKeyDto {
	principalId: string
	label: string
	/** The Access service-token Client ID (= the principal's external_id). */
	clientId: string | null
	status: PrincipalStatus
	grants: GrantDto[]
	createdAt: number
}

export interface ProvisionApiKeyRequest {
	label: string
	type: 'service'
	projectId?: string | null
	roleKey: string
	expiresAt?: number | null
}

/**
 * Provisioning result. `clientSecret` is shown by Cloudflare exactly ONCE — copy it
 * now, it is not retrievable later. `policyInclusion: 'manual'` flags that the token
 * still needs adding to the app's Service Auth policy in the dashboard (v1).
 */
export interface ProvisionApiKeyResponse {
	principalId: string
	clientId: string
	clientSecret: string
	tokenId: string
	policyInclusion: 'manual'
}

/** Rotation result — new secret shown once; token id + principal unchanged. */
export interface RotateApiKeyResponse {
	principalId: string
	clientId: string
	clientSecret: string
	tokenId: string
}

// ── Capability tokens ─────────────────────────────────────────────────────────

/** Metadata only — never the token hash or plaintext. */
export interface CapabilityListItem {
	id: string
	label: string | null
	issuedBy: string | null
	expiresAt: number | null
	maxUses: number | null
	usedCount: number
	revokedAt: number | null
	createdAt: number
	grants: { action: string; resource: string }[]
}

export interface IssueCapabilityRequest {
	grants: { action: string; resource: string; projectId?: string | null }[]
	label?: string
	expiresAt?: number
	maxUses?: number
}

/** Issued-capability result — plaintext `token` returned ONCE. */
export interface IssuedCapabilityResponse {
	id: string
	token: string
}

// ── Audit & auth log ──────────────────────────────────────────────────────────

export interface AuditEventDto {
	id: string
	requestId: string
	principalId: string | null
	principalLabel: string
	capabilityTokenId: string | null
	app: string
	action: string
	resourceType: string
	resourceId: string | null
	diff: unknown
	metadata: unknown
	createdAt: number
}

export interface AuthLogDto {
	id: number
	requestId: string
	app: string
	kind: 'authenticate' | 'redeem'
	principalId: string | null
	capabilityTokenId: string | null
	decision: 'allow' | 'deny'
	reason: string | null
	createdAt: number
}

// ── Me ────────────────────────────────────────────────────────────────────────

export interface MeDto {
	id: string
	type: PrincipalType
	label: string
	permissions: PermissionEntry[]
	/** Whether group resolution was available this request. */
	groupsUnavailable: boolean
}

export type { PermissionEntry, PermissionSource, PrincipalType }
