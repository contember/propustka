// Tiny formatting helpers shared across pages.

import type { PermissionEntry } from '@propustka/worker/admin'

/** A flat scope coordinate (one dimension + opaque value); null = global. */
type Scope = NonNullable<PermissionEntry['scope']>

/** Format a scope coordinate for display: `dimension = value`, or "Global" when null. */
export function fmtScope(scope: Scope | null): string {
	if (scope === null) return 'Global'
	return `${scope.type} = ${scope.value}`
}

/** Format an epoch-millis timestamp as a readable local date-time. */
export function fmtDate(ms: number | null | undefined): string {
	if (ms === null || ms === undefined) return '—'
	return new Date(ms).toLocaleString(undefined, {
		year: 'numeric',
		month: 'short',
		day: 'numeric',
		hour: '2-digit',
		minute: '2-digit',
	})
}

/** Format an optional expiry timestamp; `null` means "never". */
export function fmtExpiry(ms: number | null | undefined): string {
	if (ms === null || ms === undefined) return 'Never'
	return fmtDate(ms)
}

/** Build a query string from an object, skipping empty / undefined / null values. */
export function qs(params: Record<string, string | number | null | undefined>): string {
	const search = new URLSearchParams()
	for (const [key, value] of Object.entries(params)) {
		if (value === null || value === undefined) continue
		const str = String(value).trim()
		if (str === '') continue
		search.set(key, str)
	}
	const out = search.toString()
	return out ? `?${out}` : ''
}

/**
 * Parse a `<datetime-local>` input value into epoch millis, or null when empty.
 * Returns `null` for an empty field (= no expiry).
 */
export function parseDateTimeLocal(value: string): number | null {
	const trimmed = value.trim()
	if (trimmed === '') return null
	const ms = new Date(trimmed).getTime()
	return Number.isNaN(ms) ? null : ms
}
