import type { RoleDef, RoleSource } from '@propustka/core'

/**
 * Roles now live in the DB, per app (the `roles` table) — each app declares its own
 * vocabulary and reconciles it in. The ONE exception is a built-in, cross-app role
 * kept in code: `admin = ['*']`. It must resolve for ANY app (including app=null, the
 * cross-app / bootstrap path), so it can't sit in a per-app DB table. Everything else
 * is loaded from `roles` for the calling app and layered under the built-ins.
 *
 * `grants.role_key` is plain TEXT (no FK — a grant may set app=NULL while a roles row
 * always has a concrete app). Validate the key at write time against the built-ins OR
 * the app's `roles` rows; a key that resolves to nothing at read time confers zero
 * permissions (fail-closed) and shows as dangling.
 */
export const BUILTIN_ROLES: Record<string, RoleDef> = {
	admin: { name: 'Admin', permissions: ['*'] },
}

/**
 * Build a request-scoped `RoleSource` over the built-ins layered on top of an app's
 * DB roles, already loaded into `appRoles` (role_key -> def). Resolution stays PURE:
 * the caller fetches the rows up front and hands them in, so `computePermissions`
 * does no I/O. `getRole`/`listRoles` ignore the `app` arg for matching (the map is
 * already the calling app's roles); it is part of the `RoleSource` contract so a
 * future multi-app source could honor it.
 *
 * Lookup order in `getRole`: built-ins first (so `admin` resolves for every app,
 * incl. app=null), then the app's DB roles. `listRoles` unions both, built-ins last
 * so an app cannot shadow the cross-app `admin`.
 */
export function makeRoleSource(appRoles: Record<string, RoleDef>): RoleSource {
	return {
		getRole(_app: string | null, key: string): RoleDef | undefined {
			if (Object.hasOwn(BUILTIN_ROLES, key)) {
				return BUILTIN_ROLES[key]
			}
			// Object.hasOwn guards against prototype keys ('constructor', etc.).
			return Object.hasOwn(appRoles, key) ? appRoles[key] : undefined
		},
		listRoles(_app: string | null): Record<string, RoleDef> {
			return { ...appRoles, ...BUILTIN_ROLES }
		},
	}
}

/**
 * True iff `key` is a known role for `appRoles` — a built-in (e.g. `admin`) OR a row
 * in the app's loaded `roles`. The grant/mapping validation gate (app-aware).
 */
export function isKnownRole(key: string, appRoles: Record<string, RoleDef>): boolean {
	return Object.hasOwn(BUILTIN_ROLES, key) || Object.hasOwn(appRoles, key)
}
