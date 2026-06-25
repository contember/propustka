/**
 * Tiny structural readers for untrusted JSON — here, a verified-but-loosely-typed JWT
 * payload (jose returns `JWTPayload`, an index signature of `unknown`). They let `token.ts`
 * narrow claims without `as` casts: read a field, check its runtime type, proceed. Mirrors the
 * worker's own `json.ts`; kept here so the token-claim parser can live in `@propustka/core`
 * (the contract both the Worker and the SDK must agree on) with no cross-package import.
 */

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
