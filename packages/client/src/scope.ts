/**
 * Resolve the three-state scope from `scopedTo()` into a single value the app controls.
 * This is the SINGLE place the empty-`IN ()` SQL trap is handled: `none` short-circuits
 * without ever emitting `WHERE id IN ()`.
 *
 *   - `null`      → `all()`         — unrestricted (admin / global grant): no filter
 *   - `[]`        → `none()`        — no access: empty result, DO NOT query
 *   - non-empty   → `some(ids)`     — filter to these ids (`WHERE id IN (...)`)
 *
 * The app supplies what all/some/none mean for its own query; filtering must happen at the
 * data layer, never by loading everything and filtering in memory.
 */
export function applyScope<T>(
	scope: string[] | null,
	branches: { all: () => T; some: (ids: string[]) => T; none: () => T },
): T {
	if (scope === null) {
		return branches.all()
	}
	if (scope.length === 0) {
		return branches.none()
	}
	return branches.some(scope)
}
