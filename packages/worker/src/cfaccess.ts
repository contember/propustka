/**
 * Cloudflare Access API client for service-token (API-key) provisioning. The
 * Worker holds a scoped API token (*Access: Service Tokens Edit*) + account id as
 * secrets — admin-only, never exposed to app callers.
 *
 * The Access API wraps responses in `{ success, result, errors }`; we surface the
 * `result` on success and throw a `CfAccessError` carrying the messages otherwise.
 */

import { prop } from './json'

const API_BASE = 'https://api.cloudflare.com/client/v4'

export class CfAccessError extends Error {
	constructor(message: string, readonly status: number) {
		super(message)
		this.name = 'CfAccessError'
	}
}

/** A freshly minted service token. `clientSecret` is shown by Cloudflare ONCE. */
export interface MintedServiceToken {
	id: string
	clientId: string
	clientSecret: string
}

// ── Access apps + reusable policies (the edge front door) ──────────────────────
//
// The "new" Cloudflare Access model: account-level REUSABLE policies, attached to apps by id.
// Reconcile (see admin/reconcile-access.ts) creates/updates these and points each app's
// `policies` array at them. These types mirror only the fields reconcile reads/writes.

/** A Cloudflare Access policy decision. */
export type CfDecision = 'allow' | 'bypass' | 'non_identity'

/** An Access policy "include" selector — the subset reconcile emits. */
export type CfInclude =
	| { any_valid_service_token: Record<string, never> }
	| { email_domain: { domain: string } }
	| { email: { email: string } }
	| { everyone: Record<string, never> }

/** The mutable spec of a reusable Access policy (what we create / update). */
export interface CfPolicySpec {
	name: string
	decision: CfDecision
	include: CfInclude[]
}

/** A reusable Access policy as read back from the account-level policies list. */
export interface CfPolicy {
	id: string
	name: string
	decision: string
	/** How many Access apps reference this reusable policy (the delete-orphan guard). */
	appCount: number
}

/** A self_hosted destination (host or host/path). */
export interface CfDestination {
	type: string
	uri: string
}

/** An Access application as read back — the fields reconcile must preserve on a (full-replace) update. */
export interface CfApp {
	id: string
	name: string
	aud: string
	type: string
	domain: string | null
	sessionDuration: string | null
	destinations: CfDestination[]
	/** Attached policy ids, in precedence order (reusable refs + any inline). */
	policyIds: string[]
}

/** Spec to create a new self_hosted Access application. */
export interface CfAppSpec {
	name: string
	destinations: string[]
	sessionDuration?: string
}

/**
 * The Cloudflare Access surface the worker depends on — service tokens (API keys) AND the
 * apps/reusable-policies used by Access-rules reconcile. Modelled as an interface (not just the
 * concrete client) so handlers take it off `Services` and tests inject an in-memory fake — the
 * same "interface, not concrete class" seam the auth surfaces use.
 */
export interface CfAccess {
	createServiceToken(name: string, duration?: string): Promise<MintedServiceToken>
	deleteServiceToken(tokenId: string): Promise<void>
	findTokenIdByClientId(clientId: string): Promise<string | null>
	rotateServiceToken(tokenId: string): Promise<MintedServiceToken>
	listReusablePolicies(): Promise<CfPolicy[]>
	createReusablePolicy(spec: CfPolicySpec): Promise<CfPolicy>
	updateReusablePolicy(id: string, spec: CfPolicySpec): Promise<CfPolicy>
	deleteReusablePolicy(id: string): Promise<void>
	findAppByName(name: string): Promise<CfApp | null>
	createApp(spec: CfAppSpec): Promise<CfApp>
	getApp(id: string): Promise<CfApp>
	updateAppPolicies(app: CfApp, policyIds: string[]): Promise<void>
}

interface CfEnvelope {
	success: boolean
	result: unknown
	errors: { message: string }[]
}

/** Structurally validate the `{ success, result, errors }` envelope. */
function isEnvelope(value: unknown): value is CfEnvelope {
	return typeof prop(value, 'success') === 'boolean'
}

function envelopeErrors(value: CfEnvelope): string[] {
	const errors = value.errors
	if (!Array.isArray(errors)) {
		return []
	}
	const out: string[] = []
	for (const e of errors) {
		const message = prop(e, 'message')
		if (typeof message === 'string') {
			out.push(message)
		}
	}
	return out
}

/** Narrow a service-token result without an `as` cast at the deserialization boundary. */
function asServiceToken(result: unknown): MintedServiceToken {
	const id = prop(result, 'id')
	const clientId = prop(result, 'client_id')
	const clientSecret = prop(result, 'client_secret')
	if (typeof id !== 'string' || typeof clientId !== 'string' || typeof clientSecret !== 'string') {
		throw new CfAccessError('Cloudflare Access API returned an unexpected service-token shape', 502)
	}
	return { id, clientId, clientSecret }
}

/** Narrow a reusable-policy result. `app_count` defaults to 0 when absent. */
function asPolicy(result: unknown): CfPolicy {
	const id = prop(result, 'id')
	const name = prop(result, 'name')
	const decision = prop(result, 'decision')
	if (typeof id !== 'string' || typeof name !== 'string' || typeof decision !== 'string') {
		throw new CfAccessError('Cloudflare Access API returned an unexpected policy shape', 502)
	}
	const appCount = prop(result, 'app_count')
	return { id, name, decision, appCount: typeof appCount === 'number' ? appCount : 0 }
}

/** Narrow an app's `destinations` array to `{ type, uri }[]`, skipping malformed entries. */
function asDestinations(value: unknown): CfDestination[] {
	if (!Array.isArray(value)) {
		return []
	}
	const out: CfDestination[] = []
	for (const item of value) {
		const type = prop(item, 'type')
		const uri = prop(item, 'uri')
		if (typeof type === 'string' && typeof uri === 'string') {
			out.push({ type, uri })
		}
	}
	return out
}

/** Collect the `id`s from an app's `policies` array, in order. */
function asPolicyIds(value: unknown): string[] {
	if (!Array.isArray(value)) {
		return []
	}
	const out: string[] = []
	for (const item of value) {
		const id = prop(item, 'id')
		if (typeof id === 'string') {
			out.push(id)
		}
	}
	return out
}

/** Narrow an Access-app result to the fields reconcile reads (and must echo back on update). */
function asApp(result: unknown): CfApp {
	const id = prop(result, 'id')
	const name = prop(result, 'name')
	const aud = prop(result, 'aud')
	const type = prop(result, 'type')
	if (typeof id !== 'string' || typeof name !== 'string' || typeof aud !== 'string' || typeof type !== 'string') {
		throw new CfAccessError('Cloudflare Access API returned an unexpected app shape', 502)
	}
	const domain = prop(result, 'domain')
	const sessionDuration = prop(result, 'session_duration')
	return {
		id,
		name,
		aud,
		type,
		domain: typeof domain === 'string' ? domain : null,
		sessionDuration: typeof sessionDuration === 'string' ? sessionDuration : null,
		destinations: asDestinations(prop(result, 'destinations')),
		policyIds: asPolicyIds(prop(result, 'policies')),
	}
}

/** Build the request body for a reusable-policy create/update (exclude/require always empty). */
function policyBody(spec: CfPolicySpec): { name: string; decision: CfDecision; include: CfInclude[]; exclude: never[]; require: never[] } {
	return { name: spec.name, decision: spec.decision, include: spec.include, exclude: [], require: [] }
}

export class CfAccessClient implements CfAccess {
	constructor(
		private readonly apiToken: string,
		private readonly accountId: string,
	) {}

	/** Make a request and return the validated `result` field as `unknown` for the caller to narrow. */
	private async request(method: string, path: string, body?: unknown): Promise<unknown> {
		const response = await fetch(`${API_BASE}${path}`, {
			method,
			headers: {
				authorization: `Bearer ${this.apiToken}`,
				'content-type': 'application/json',
			},
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		})
		const payload: unknown = await response.json()
		if (!isEnvelope(payload) || !response.ok || !payload.success) {
			const detail = isEnvelope(payload) ? envelopeErrors(payload).join('; ') || response.statusText : response.statusText
			throw new CfAccessError(`Cloudflare Access API ${method} ${path} failed: ${detail}`, response.status)
		}
		return payload.result
	}

	/**
	 * Mint a service token. `duration` bounds its life — a Go-style duration (e.g.
	 * '8760h', '3600s') or the literal 'forever' for a non-expiring token (Access maps
	 * it to ~100 years). When omitted, Access defaults to 1 year (8760h).
	 * `client_secret` is returned exactly once — surface it to the caller/UI
	 * immediately; never persist it.
	 */
	async createServiceToken(name: string, duration?: string): Promise<MintedServiceToken> {
		const result = await this.request(
			'POST',
			`/accounts/${this.accountId}/access/service_tokens`,
			duration === undefined ? { name } : { name, duration },
		)
		return asServiceToken(result)
	}

	/** Delete a service token (revocation / best-effort rollback after a mid-flow failure). */
	async deleteServiceToken(tokenId: string): Promise<void> {
		await this.request('DELETE', `/accounts/${this.accountId}/access/service_tokens/${tokenId}`)
	}

	/**
	 * Resolve the Access token *id* from a stored `client_id`. The IAM principal
	 * persists the client_id as `external_id` (the schema has no column for the token
	 * id), so revoke/rotate look the id up here. Returns null when not found
	 * (already deleted in Access). The list is paginated; we scan pages until matched.
	 */
	async findTokenIdByClientId(clientId: string): Promise<string | null> {
		let page = 1
		// Bounded scan — at internal scale there are tens of tokens, a couple of pages.
		for (; page <= 100; page++) {
			const result = await this.request(
				'GET',
				`/accounts/${this.accountId}/access/service_tokens?per_page=50&page=${page}`,
			)
			if (!Array.isArray(result) || result.length === 0) {
				return null
			}
			for (const item of result) {
				if (prop(item, 'client_id') === clientId) {
					const id = prop(item, 'id')
					return typeof id === 'string' ? id : null
				}
			}
			if (result.length < 50) {
				return null
			}
		}
		return null
	}

	/**
	 * Rotate a token's secret — token id and IAM principal unchanged. Returns the
	 * new `client_secret` once. Plan for rotation from day one so a year-out mass
	 * expiry doesn't surprise us.
	 */
	async rotateServiceToken(tokenId: string): Promise<MintedServiceToken> {
		const result = await this.request(
			'POST',
			`/accounts/${this.accountId}/access/service_tokens/${tokenId}/rotate`,
		)
		return asServiceToken(result)
	}

	// ── Reusable policies (account-level) ───────────────────────────────────────

	/** List every account-level reusable policy (paginated, bounded scan). */
	async listReusablePolicies(): Promise<CfPolicy[]> {
		const out: CfPolicy[] = []
		for (let page = 1; page <= 100; page++) {
			const result = await this.request('GET', `/accounts/${this.accountId}/access/policies?per_page=50&page=${page}`)
			if (!Array.isArray(result) || result.length === 0) {
				break
			}
			for (const item of result) {
				out.push(asPolicy(item))
			}
			if (result.length < 50) {
				break
			}
		}
		return out
	}

	/** Create a reusable policy; returns it with its new id. */
	async createReusablePolicy(spec: CfPolicySpec): Promise<CfPolicy> {
		const result = await this.request('POST', `/accounts/${this.accountId}/access/policies`, policyBody(spec))
		return asPolicy(result)
	}

	/** Update a reusable policy in place (id stable). */
	async updateReusablePolicy(id: string, spec: CfPolicySpec): Promise<CfPolicy> {
		const result = await this.request('PUT', `/accounts/${this.accountId}/access/policies/${id}`, policyBody(spec))
		return asPolicy(result)
	}

	/** Delete a reusable policy (also detaches it from any app referencing it). */
	async deleteReusablePolicy(id: string): Promise<void> {
		await this.request('DELETE', `/accounts/${this.accountId}/access/policies/${id}`)
	}

	// ── Access applications ─────────────────────────────────────────────────────

	/** Find a self_hosted app by exact name (paginated scan); null when absent. */
	async findAppByName(name: string): Promise<CfApp | null> {
		for (let page = 1; page <= 100; page++) {
			const result = await this.request('GET', `/accounts/${this.accountId}/access/apps?per_page=50&page=${page}`)
			if (!Array.isArray(result) || result.length === 0) {
				return null
			}
			for (const item of result) {
				if (prop(item, 'name') === name) {
					return asApp(item)
				}
			}
			if (result.length < 50) {
				return null
			}
		}
		return null
	}

	/** Create a self_hosted Access application (no policies yet — reconcile attaches them next). */
	async createApp(spec: CfAppSpec): Promise<CfApp> {
		const result = await this.request('POST', `/accounts/${this.accountId}/access/apps`, {
			name: spec.name,
			domain: spec.destinations[0],
			type: 'self_hosted',
			session_duration: spec.sessionDuration ?? '24h',
			destinations: spec.destinations.map((uri) => ({ type: 'public', uri })),
		})
		return asApp(result)
	}

	/** Read one Access app (for its base fields before a policies-only update). */
	async getApp(id: string): Promise<CfApp> {
		const result = await this.request('GET', `/accounts/${this.accountId}/access/apps/${id}`)
		return asApp(result)
	}

	/**
	 * Repoint an app's `policies` at `policyIds` (precedence = array order). The app PUT is a
	 * FULL replace, so we echo back the app's own base fields and change only `policies`. This is
	 * the atomic attach-and-detach: inline/legacy policies embedded in the old array simply drop
	 * off. Callers must never pass an empty `policyIds` (that would leave the app policy-less).
	 */
	async updateAppPolicies(app: CfApp, policyIds: string[]): Promise<void> {
		await this.request('PUT', `/accounts/${this.accountId}/access/apps/${app.id}`, {
			name: app.name,
			domain: app.domain ?? app.destinations[0]?.uri ?? app.name,
			type: app.type,
			session_duration: app.sessionDuration ?? '24h',
			destinations: app.destinations.map((d) => ({ type: d.type, uri: d.uri })),
			policies: policyIds.map((id, index) => ({ id, precedence: index + 1 })),
		})
	}
}

/**
 * Whether a freshly minted service token is already admitted at the Access edge. `'automatic'`
 * once the target app carries a reconciled `service-auth` policy ("any valid service token" — see
 * admin/reconcile-access.ts), so no dashboard step is needed; `'manual'` only for an app that has
 * not yet had its Access rules reconciled (the operator must add the token by hand).
 */
export type PolicyInclusion = 'automatic' | 'manual'
