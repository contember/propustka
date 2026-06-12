export type PrincipalType = 'user' | 'service'

/**
 * Where a resolved permission entry came from. Used for debuggability in the admin UI
 * ("why does this user have this permission?"); `can()`/`scopedTo()` ignore it.
 *  - 'grant'             — explicit `grants` row
 *  - 'bootstrap'         — IAM_BOOTSTRAP_ADMINS env match (resolution-time only)
 *  - `group:${groupRef}` — IdP group → role mapping (the `<org>/<team>` ref)
 */
export type PermissionSource = 'grant' | 'bootstrap' | `group:${string}`

/**
 * A flat, app-owned scope coordinate — one dimension (`type`) and an opaque value.
 * Dimensions are INDEPENDENT: there is NO hierarchy/containment between them.
 * `value` is an opaque app-owned string; core never validates it.
 */
export interface Scope {
	type: string
	value: string
}

export interface PermissionEntry {
	action: string
	/** null = global / all scopes */
	scope: Scope | null
	source: PermissionSource
}

/**
 * Domain event apps emit. Only the app knows what changed.
 *
 * IMPORTANT: `diff`/`metadata` may carry sensitive values (settings can hold secrets).
 * The app MUST redact secret material before passing them — audit storage is verbatim
 * and long-lived; the IAM Worker stores what it receives as-is.
 */
export interface DomainEvent {
	action: string
	resourceType: string
	resourceId?: string
	diff?: unknown
	metadata?: unknown
}

export interface RoleDef {
	name: string
	description?: string
	permissions: string[]
}

/** One scope dimension an app exposes (flat, independent). */
export interface AppScopeDef {
	type: string
	label?: string
}

/** One action in an app's catalog (used for validation + admin UI discovery). */
export interface AppActionDef {
	action: string
	description?: string
}

/** An app's full authz vocabulary, declared in the app's code, reconciled into Propustka. */
export interface AppSchema {
	scopes: AppScopeDef[]
	actions: AppActionDef[]
	/** role_key -> def; these are origin='app' roles. */
	roles: Record<string, RoleDef>
}

/**
 * App-aware role lookup. The worker layers a built-in cross-app source (admin) over a
 * per-app DB source. `app` is the calling app id; null = cross-app/built-in only.
 */
export interface RoleSource {
	getRole(app: string | null, key: string): RoleDef | undefined
	listRoles(app: string | null): Record<string, RoleDef>
}
