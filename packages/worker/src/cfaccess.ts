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

export class CfAccessClient {
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
	 * Mint a service token. `duration` (e.g. '8760h') optionally bounds its life.
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
}

// TODO(v1): automate Service Auth policy inclusion if the Access policy API
// supports it. For now `provisionApiKey` returns policyInclusion: 'manual' and the
// operator adds the token to the target app's Service Auth policy in the dashboard.
// This cannot be verified here against real Access, so option (b) per spec step 6.
export type PolicyInclusion = 'manual'
