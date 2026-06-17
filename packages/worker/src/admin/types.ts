// @propustka/worker/admin — admin REST request/response DTOs.
//
// Consumed type-only by @propustka/admin-ui (the opice dashboard pattern: end-to-end
// typed, no codegen). Reuses @propustka/core types where they fit. Keep these clean
// and complete — they ARE the admin API contract.

import type {
	AccessAppDecl,
	AccessRule,
	AppAccess,
	AppActionDef,
	AppSchema,
	AppScopeDef,
	PermissionEntry,
	PermissionSource,
	PrincipalType,
	RoleDef,
} from '@propustka/core'

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
	/** Named role/policy key; null for an inline grant (then `permissions` is set). */
	roleKey: string | null
	/** Inline action-pattern set; null for a role-based grant (then `roleKey` is set). */
	permissions: string[] | null
	/** Scope dimension; null = global (both rise/fall together). */
	scopeType: string | null
	/** Opaque, app-owned scope value; null = global. */
	scopeValue: string | null
	/** App id this grant applies to; null = all apps (cross-app). */
	app: string | null
	grantedBy: string | null
	expiresAt: number | null
	createdAt: number
	/** True when `roleKey` is set but no longer resolves to a known role (zero perms). */
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
	/** A named role/policy key — XOR `permissions` (supply exactly one). */
	roleKey?: string
	/** An inline action-pattern set — XOR `roleKey` (supply exactly one). */
	permissions?: string[]
	/** Scope dimension; null / omitted = global. Both-or-neither with `scopeValue`. */
	scopeType?: string | null
	/** Opaque, app-owned scope value; null / omitted = global. */
	scopeValue?: string | null
	/** App id (an ACCESS_APPS value); null / omitted = all apps (cross-app). */
	app?: string | null
	expiresAt?: number | null
}

// ── Group → role mappings ─────────────────────────────────────────────────────

export interface GroupMappingDto {
	id: string
	provider: string
	groupRef: string
	roleKey: string
	scopeType: string | null
	scopeValue: string | null
	/** App id this mapping applies to; null = all apps. */
	app: string | null
	createdAt: number
	/** True when `roleKey` no longer resolves to a known role for the app. */
	dangling: boolean
}

export interface CreateGroupMappingRequest {
	provider: string
	groupRef: string
	roleKey: string
	scopeType?: string | null
	scopeValue?: string | null
	/** App id (an ACCESS_APPS value); null / omitted = all apps. */
	app?: string | null
}

// ── Apps (read-only; derived from ACCESS_APPS) ────────────────────────────────

/** The set of app ids propustka serves — the choices for a grant/mapping's `app`. */
export interface AppDto {
	id: string
}

// ── Roles & policies (per-app, DB-backed) ─────────────────────────────────────

/** A role available for the calling app — a built-in or a DB row (app/custom). */
export interface RoleDto {
	key: string
	name: string
	description?: string
	permissions: string[]
	/** 'builtin' (cross-app, e.g. admin), 'app' (reconciled), or 'custom' (admin-made). */
	origin: 'builtin' | 'app' | 'custom'
}

// ── App schema (reconciled vocabulary) ────────────────────────────────────────

/** Reconcile an app's vocabulary. The request body IS the core `AppSchema`. */
export type PutAppSchemaRequest = AppSchema

/** GET schema response — the app's scopes, actions, and origin='app' roles. */
export interface AppSchemaDto {
	app: string
	scopes: AppScopeDef[]
	actions: AppActionDef[]
	/** role_key -> def, origin='app' only (reconciled from code). */
	roles: Record<string, RoleDef>
}

// ── Access edge rules (reconciled into Cloudflare as reusable policies) ─────────

/** Reconcile an app's Access edge rules. The request body IS the core `AppAccess`. */
export type PutAppAccessRequest = AppAccess

/** One managed reusable policy in the live readback (parsed from its `px:<app>:<key>:<kind>` name). */
export interface AccessPolicyDto {
	/** The CF-app key this policy belongs to. */
	key: string
	/** The rule kind — 'service-auth' | 'human' | 'public'. */
	kind: string
	/** The managed policy name. */
	name: string
	/** The Cloudflare decision — 'allow' | 'bypass' | 'non_identity'. */
	decision: string
	/** How many CF apps reference it (1 in steady state; 0 = orphan). */
	appCount: number
}

/** GET/PUT access response — the reusable policies propustka manages for this app (live CF state). */
export interface AppAccessDto {
	app: string
	policies: AccessPolicyDto[]
}

// ── Policies (origin='custom' roles, admin-composed) ──────────────────────────

/** A custom policy (an origin='custom' role row) for an app. */
export interface PolicyDto {
	app: string
	key: string
	name: string
	description?: string
	permissions: string[]
	createdAt: number
}

export interface CreatePolicyRequest {
	key: string
	name: string
	description?: string
	permissions: string[]
}

export interface UpdatePolicyRequest {
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
	/** A named role/policy key — XOR `permissions` (supply exactly one). */
	roleKey?: string
	/** An inline action-pattern set — XOR `roleKey` (supply exactly one). */
	permissions?: string[]
	/** Scope dimension; null / omitted = global. Both-or-neither with `scopeValue`. */
	scopeType?: string | null
	/** Opaque, app-owned scope value; null / omitted = global. */
	scopeValue?: string | null
	/** App id (an ACCESS_APPS value); null / omitted = all apps. */
	app?: string | null
	expiresAt?: number | null
}

/**
 * Provisioning result. `clientSecret` is shown by Cloudflare exactly ONCE — copy it
 * now, it is not retrievable later. `policyInclusion` is `'automatic'` when the target app already
 * carries a reconciled `service-auth` policy ("any valid service token"), so the token works with
 * no dashboard step; `'manual'` when the app's Access rules haven't been reconciled and the
 * operator must add the token to its Service Auth policy by hand.
 */
export interface ProvisionApiKeyResponse {
	principalId: string
	clientId: string
	clientSecret: string
	tokenId: string
	policyInclusion: 'automatic' | 'manual'
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
	/** `scope` is the delegation-check coordinate only (not stored); omitted → global. */
	grants: { action: string; resource: string; scope?: { type: string; value: string } | null }[]
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

export type { AccessAppDecl, AccessRule, AppAccess, AppActionDef, AppSchema, AppScopeDef, PermissionEntry, PermissionSource, PrincipalType, RoleDef }
