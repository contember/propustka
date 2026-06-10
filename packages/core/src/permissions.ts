import type { PermissionEntry } from './types'

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
 *  - projectScope === undefined → scope-less: ONLY entries with projectId === null satisfy.
 *  - projectScope === <id>      → entries with projectId === null OR projectId === <id> satisfy.
 *
 * Within the satisfying entries, the entry's `action` is matched against the requested
 * `action` using `matchAction` (so a wildcard entry like 'project.*' grants 'project.read').
 */
export function permits(entries: PermissionEntry[], action: string, projectScope?: string): boolean {
	for (const entry of entries) {
		const scopeOk = entry.projectId === null || entry.projectId === projectScope
		if (scopeOk && matchAction(entry.action, action)) {
			return true
		}
	}
	return false
}
