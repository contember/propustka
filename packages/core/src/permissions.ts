import type { PermissionEntry, Scope } from './types'

/**
 * Wildcard action matching. The pattern is one of:
 *  - '*'        — matches every action
 *  - 'prefix.*' — matches the `prefix` namespace and anything nested under it
 *                 (e.g. 'project.*' matches 'project.read' and 'project.settings.update',
 *                  but NOT 'projects.read' — the boundary is the dot)
 *  - exact      — matches only that exact action string
 *
 * Examples:
 *   matchAction('*', 'x.y')                          === true
 *   matchAction('project.*', 'project.read')         === true
 *   matchAction('project.*', 'project.settings.update') === true
 *   matchAction('project.read', 'project.read')      === true
 *   matchAction('project.read', 'project.write')     === false
 *   matchAction('project.*', 'projects.read')        === false
 */
export function matchAction(pattern: string, action: string): boolean {
	if (pattern === '*') {
		return true
	}
	if (pattern.endsWith('.*')) {
		// Drop the trailing '*' (keep the dot) so 'project.*' yields 'project.' —
		// the action must start with that prefix, which enforces the dot boundary.
		const prefix = pattern.slice(0, -1)
		return action.startsWith(prefix)
	}
	return pattern === action
}

/**
 * Does `entries` grant `action` at the given scope? Mirrors `can()` semantics exactly:
 *  - scope === undefined → scope-less: ONLY entries with scope === null satisfy (global perms only).
 *  - scope === <Scope>   → entries with scope === null OR an entry scoped to the SAME
 *                          (type, value) pair satisfy.
 *
 * Within the satisfying entries, the entry's `action` is matched against the requested
 * `action` using `matchAction` (so a wildcard entry like 'project.*' grants 'project.read').
 */
export function permits(entries: PermissionEntry[], action: string, scope?: Scope): boolean {
	for (const entry of entries) {
		const scopeOk = entry.scope === null
			|| (scope !== undefined && entry.scope.type === scope.type && entry.scope.value === scope.value)
		if (scopeOk && matchAction(entry.action, action)) {
			return true
		}
	}
	return false
}

/**
 * The set of scope values `entries` grant `action` on within a single `dimension`
 * (scope type) — the resolution behind `scopedTo()`, shared so the real SDK context and
 * any fake/test context agree exactly:
 *   - `null`      → unrestricted: a matching GLOBAL entry (scope === null) exists, so the
 *                   principal holds the action everywhere (e.g. an admin / app-wide grant);
 *   - non-empty   → exactly the scope values of the matching entries scoped to `dimension`;
 *   - `[]`        → no matching entry: no scoped access at all within `dimension`.
 * A matching global entry short-circuits to `null` (it dominates any scoped entries).
 * Entries scoped to a DIFFERENT dimension are ignored (they say nothing about `dimension`).
 */
export function scopedValues(entries: PermissionEntry[], action: string, dimension: string): string[] | null {
	const values: string[] = []
	const seen = new Set<string>()
	for (const entry of entries) {
		if (!matchAction(entry.action, action)) {
			continue
		}
		if (entry.scope === null) {
			return null
		}
		// A grant in another dimension neither restricts nor widens this one — skip it.
		if (entry.scope.type !== dimension) {
			continue
		}
		if (!seen.has(entry.scope.value)) {
			seen.add(entry.scope.value)
			values.push(entry.scope.value)
		}
	}
	return values
}

/**
 * Validate a role/policy/inline action PATTERN against an app's action `catalog`.
 * The catalog holds concrete action strings the app actually exposes (no wildcards).
 *  - '*'          → always valid (the universal wildcard).
 *  - exact match  → valid iff the catalog contains the pattern verbatim.
 *  - 'prefix.*'   → valid iff some catalog action starts with `prefix.` (i.e. the
 *                   namespace is non-empty), so we never grant a wildcard over nothing.
 *  - otherwise    → invalid.
 */
export function isActionAllowed(pattern: string, catalog: readonly string[]): boolean {
	if (pattern === '*') {
		return true
	}
	if (catalog.includes(pattern)) {
		return true
	}
	if (pattern.endsWith('.*')) {
		// Keep the dot ('prefix.*' -> 'prefix.') so the namespace boundary is enforced and
		// the wildcard only validates when the app exposes at least one action under it.
		const prefix = pattern.slice(0, -1)
		return catalog.some((entry) => entry.startsWith(prefix))
	}
	return false
}
