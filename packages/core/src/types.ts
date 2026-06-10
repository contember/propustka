export type PrincipalType = 'user' | 'service'

/**
 * Where a resolved permission entry came from. Used for debuggability in the admin UI
 * ("why does this user have this permission?"); `can()`/`scopedTo()` ignore it.
 *  - 'grant'             — explicit `grants` row
 *  - 'bootstrap'         — IAM_BOOTSTRAP_ADMINS env match (resolution-time only)
 *  - `group:${groupRef}` — IdP group → role mapping (the `<org>/<team>` ref)
 */
export type PermissionSource = 'grant' | 'bootstrap' | `group:${string}`

export interface PermissionEntry {
	action: string
	/** null = global / all projects */
	projectId: string | null
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

export interface RoleSource {
	getRole(key: string): RoleDef | undefined
	listRoles(): Record<string, RoleDef>
}
