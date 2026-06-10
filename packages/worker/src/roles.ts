import type { RoleDef, RoleSource } from '@propustka/core'

/**
 * Role → permission bundles, defined in code (single source of truth). We have
 * ~3 stable roles; runtime role editing is admin surface we don't need, and
 * code-defined roles are versioned and deployed like everything else.
 *
 * `grants.role_key` / `group_role_mappings.role_key` are plain TEXT (no FK —
 * there is no roles table). Validate the key against this registry at
 * grant/mapping/api-key creation time; a key that no longer exists in code
 * resolves to zero permissions (fail-closed) and shows as dangling in the UI.
 */
export const ROLES: Record<string, RoleDef> = {
	admin: { name: 'Admin', permissions: ['*'] },
	editor: { name: 'Editor', permissions: ['project.*', 'report.*'] },
	viewer: { name: 'Viewer', permissions: ['project.read', 'report.read'] },
}

/**
 * The only abstraction point: resolution runs against this small interface so a
 * D1-backed source could replace the code registry later without touching
 * permission resolution. Do NOT build the D1 variant now.
 */
export const codeRoleSource: RoleSource = {
	getRole(key: string): RoleDef | undefined {
		// Object.hasOwn guards against prototype keys ('constructor', etc.) being
		// treated as roles.
		return Object.hasOwn(ROLES, key) ? ROLES[key] : undefined
	},
	listRoles(): Record<string, RoleDef> {
		return ROLES
	},
}

/** True iff `key` is a known role in the registry — the grant/mapping validation gate. */
export function isKnownRole(key: string): boolean {
	return codeRoleSource.getRole(key) !== undefined
}
