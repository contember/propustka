import { RESOLUTION_TTL_MS, TtlCache } from './cache'
import { prop } from './json'

/**
 * IdP group-membership resolution via the Cloudflare Access get-identity endpoint.
 * USERS ONLY — service tokens have no IdP groups; skip this for them entirely.
 *
 * GitHub org/team membership is NOT in the app JWT (the token carries a subset of
 * identity due to cookie size limits), so we fetch it server-side here to drive
 * the group → role mapping.
 *
 * NOTE: verify against a real Access-protected host. This is the one external
 * integration point in group resolution and cannot be verified here against real
 * Access; it is implemented to the spec.
 */

/** Outcome of a group lookup. `unavailable` degrades to explicit grants only. */
export type GroupResult =
	| { unavailable: false; groups: string[] }
	| { unavailable: true; groups: [] }

/**
 * Normalize a GitHub org/team pair to the canonical `group_ref` used in
 * `group_role_mappings`.
 *
 * NORMALIZATION (must match admin input and identity data exactly):
 *   - form is `<org>/<team>` joined by a single '/'
 *   - both parts are lowercased
 *   - surrounding whitespace is trimmed
 *   - the *team slug* is used, not the display name (the slug is what GitHub uses
 *     in URLs/API; the display name may contain spaces/casing that won't match)
 * Examples:
 *   normalizeGroupRef('My-Org', 'Core-Devs')  === 'my-org/core-devs'
 *   normalizeGroupRef(' Acme ', ' Platform ') === 'acme/platform'
 */
export function normalizeGroupRef(org: string, team: string): string {
	return `${org.trim().toLowerCase()}/${team.trim().toLowerCase()}`
}

/**
 * Extract normalized `<org>/<team>` refs from a get-identity response body.
 * Pure — separated from the network call so it is unit-testable.
 *
 * Access surfaces GitHub teams under an IdP `groups` array. The shape varies by
 * IdP connector; GitHub teams arrive as either:
 *   - an object `{ name, id, ... }` whose `name` is already `org/team` slug form, or
 *   - a bare `org/team` string.
 * We accept both and normalize; anything not in `org/team` shape is ignored.
 */
export function parseGroupRefs(identity: unknown): string[] {
	const groups = prop(identity, 'groups')
	if (!Array.isArray(groups)) {
		return []
	}
	const refs = new Set<string>()
	for (const group of groups) {
		const raw = groupName(group)
		if (raw === undefined) {
			continue
		}
		const slash = raw.indexOf('/')
		if (slash <= 0 || slash === raw.length - 1) {
			// Not in `org/team` shape — skip (e.g. a flat group with no team part).
			continue
		}
		const org = raw.slice(0, slash)
		const team = raw.slice(slash + 1)
		refs.add(normalizeGroupRef(org, team))
	}
	return [...refs]
}

function groupName(group: unknown): string | undefined {
	if (typeof group === 'string') {
		return group
	}
	const name = prop(group, 'name')
	if (typeof name === 'string') {
		return name
	}
	return undefined
}

export class IdentityClient {
	// Keyed by principal id — membership is per-user and cached for the same short
	// TTL as resolved principals (tens of seconds). Membership does not change by
	// the second, and get-identity is an extra network call; do not call it on
	// every request uncached.
	private readonly cache = new TtlCache<string[]>(RESOLUTION_TTL_MS)

	/**
	 * Fetch the user's normalized group refs. `origin` is the CALLING APP'S OWN
	 * origin (scheme + host of the incoming request), not the team domain: the
	 * `CF_Authorization` cookie is domain-scoped to the protected app's hostname,
	 * so calling the team domain with an app-domain cookie would not authenticate.
	 * The `/cdn-cgi/access/*` path is served by the Access edge on every protected
	 * hostname and never reaches the app Worker, so there is no recursion.
	 *
	 * On failure: do NOT hard-fail auth — return `unavailable` so resolution falls
	 * back to explicit grants and sets `groupsUnavailable: true`. Group data is
	 * login-time, not live: removing a GitHub team membership only takes effect
	 * when the user's Access session next refreshes against the IdP.
	 */
	async getGroups(principalId: string, cookie: string | null, origin: string | null): Promise<GroupResult> {
		const cached = this.cache.get(principalId)
		if (cached !== undefined) {
			return { unavailable: false, groups: cached }
		}
		if (!cookie || !origin) {
			// No cookie/origin to forward → groups cannot be resolved this request.
			// Degrade rather than deny.
			return { unavailable: true, groups: [] }
		}

		let identity: unknown
		try {
			const response = await fetch(`${origin}/cdn-cgi/access/get-identity`, {
				headers: { cookie: `CF_Authorization=${cookie}` },
			})
			if (!response.ok) {
				return { unavailable: true, groups: [] }
			}
			identity = await response.json()
		} catch {
			return { unavailable: true, groups: [] }
		}

		const groups = parseGroupRefs(identity)
		this.cache.set(principalId, groups)
		return { unavailable: false, groups }
	}
}
