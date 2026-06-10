/**
 * Per-isolate cache with a short TTL (tens of seconds). Used for resolved
 * principals (incl. group membership) and group-membership lookups. The TTL
 * matches Access session-revocation latency anyway, so staleness here is in line
 * with the rest of the system. The cache must be safe to be empty: a miss simply
 * falls through to D1 / get-identity, so an empty isolate is always correct.
 *
 * Lives at module scope (one map per isolate, like jose's JWKS cache) so it
 * survives across requests handled by the same isolate.
 */
export class TtlCache<V> {
	private readonly store = new Map<string, { value: V; expiresAt: number }>()

	constructor(private readonly ttlMs: number) {}

	get(key: string): V | undefined {
		const hit = this.store.get(key)
		if (!hit) {
			return undefined
		}
		if (hit.expiresAt <= Date.now()) {
			this.store.delete(key)
			return undefined
		}
		return hit.value
	}

	set(key: string, value: V): void {
		this.store.set(key, { value, expiresAt: Date.now() + this.ttlMs })
	}

	delete(key: string): void {
		this.store.delete(key)
	}
}

/** Short TTL for resolved principals and group membership (tens of seconds). */
export const RESOLUTION_TTL_MS = 30_000
