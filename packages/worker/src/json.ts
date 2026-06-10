/**
 * Tiny structural readers for untrusted JSON (request bodies, external API
 * responses). They let us narrow `unknown` at the deserialization boundary without
 * `as` casts: read a field, check its runtime type, proceed.
 */

/** `JSON.parse` typed to return `unknown` (the built-in returns `any`). */
export function parseJson(text: string): unknown {
	return JSON.parse(text)
}

/** Read a property off an unknown value (undefined when absent / not an object). */
export function prop(value: unknown, key: string): unknown {
	if (typeof value !== 'object' || value === null) {
		return undefined
	}
	return Object.hasOwn(value, key) ? Reflect.get(value, key) : undefined
}

export function stringField(value: unknown, key: string): string | undefined {
	const v = prop(value, key)
	return typeof v === 'string' ? v : undefined
}

export function numberField(value: unknown, key: string): number | undefined {
	const v = prop(value, key)
	return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

export function booleanField(value: unknown, key: string): boolean | undefined {
	const v = prop(value, key)
	return typeof v === 'boolean' ? v : undefined
}

/** A nullable string field: distinguishes explicit `null` from absent (undefined). */
export function nullableStringField(value: unknown, key: string): string | null | undefined {
	const v = prop(value, key)
	if (v === null) {
		return null
	}
	return typeof v === 'string' ? v : undefined
}
