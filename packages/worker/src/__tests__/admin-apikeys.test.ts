import { parseAccessClaims, permits } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, jwtVerify } from 'jose'
import { handleAdmin } from '../admin/router'
import type { ProvisionApiKeyResponse, RotateApiKeyResponse } from '../admin/types'
import type { Services } from '../services'
import { getSigner } from '../signing'
import { mintFromKey } from '../tokens'
import { FakeCfAccess } from './helpers/fake-cfaccess'
import { createHarness, DEFAULT_AUD, type Harness, seedAppAction, seedGrant, seedUser } from './helpers/harness'

// End-to-end tests for the admin /api-keys flow minting a propustka-NATIVE key: provision creates a
// native service principal + grant and returns a `px_` key that `mintFromKey` resolves to the service
// principal's permissions; rotate invalidates the old one; revoke kills it. No Cloudflare Access.

const ORIGIN = 'https://iam.example.com'
const ISSUER = 'https://propustka.test'
const SIGN_ENV = { PROPUSTKA_SIGNING_KEYS: '', ENVIRONMENT: 'local' }

class FakeExecutionContext implements ExecutionContext {
	readonly props: unknown = undefined
	waitUntil(_promise: Promise<unknown>): void {}
	passThroughOnException(): void {}
}

function services(h: Harness, cf: FakeCfAccess): Services {
	return h.makeServices({ environment: 'stage', accessApps: { [DEFAULT_AUD]: 'iam-admin', 'aud-opice': 'opice' }, cfAccess: cf, issuer: ISSUER })
}

async function asAdmin(h: Harness): Promise<string> {
	const id = seedUser(h.sqlite, { sub: 'sub-admin', email: 'admin@example.com' })
	seedGrant(h.sqlite, id, 'admin', null)
	return h.signToken({ email: 'admin@example.com', sub: 'sub-admin' })
}

function req(path: string, method: string, token: string, body?: unknown): Request {
	const headers = new Headers({ 'Cf-Access-Jwt-Assertion': token })
	if (method !== 'GET') {
		headers.set('Origin', ORIGIN)
		headers.set('Content-Type', 'application/json')
	}
	return new Request(`${ORIGIN}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })
}

function run(h: Harness, cf: FakeCfAccess, request: Request): Promise<Response> {
	return handleAdmin(request, services(h, cf), new FakeExecutionContext())
}

/** Resolve a `px_` key into an access token via mintFromKey, returning the verified claims (or null). */
async function resolveKey(h: Harness, cf: FakeCfAccess, key: string) {
	const { result } = await mintFromKey(services(h, cf), SIGN_ENV, { app: 'opice', key, requestId: 'r' })
	if (!result.ok) {
		return { failed: result.reason }
	}
	const { payload } = await jwtVerify(result.token, createLocalJWKSet((await getSigner(SIGN_ENV)).jwks()), { issuer: ISSUER, audience: 'opice' })
	return { claims: parseAccessClaims(payload) }
}

async function provision(h: Harness, cf: FakeCfAccess, token: string): Promise<ProvisionApiKeyResponse> {
	seedAppAction(h.sqlite, 'opice', 'report.write') // inline grants validate against the app's catalog
	const res = await run(
		h,
		cf,
		req('/admin/api-keys', 'POST', token, { label: 'opice CI', type: 'service', permissions: ['report.write'], app: 'opice' }),
	)
	expect(res.status).toBe(201)
	return res.json()
}

describe('POST /admin/api-keys — native key', () => {
	test('returns a px_ key that resolves to the service principal permissions', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)

		const body = await provision(h, cf, token)
		expect(body.apiKey.startsWith('px_')).toBe(true)

		const resolved = await resolveKey(h, cf, body.apiKey)
		expect(resolved.claims?.ptype).toBe('service')
		expect(resolved.claims?.sub).toBe(body.principalId)
		expect(permits(resolved.claims?.perms ?? [], 'report.write')).toBe(true)
		expect(permits(resolved.claims?.perms ?? [], 'report.delete')).toBe(false)
	})
})

describe('rotate / revoke invalidate the native key', () => {
	test('rotate issues a new key and kills the old', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const first = await provision(h, cf, token)

		const rotateRes = await run(h, cf, req(`/admin/api-keys/${first.principalId}/rotate`, 'POST', token))
		expect(rotateRes.status).toBe(200)
		const rotated: RotateApiKeyResponse = await rotateRes.json()
		expect(rotated.apiKey.startsWith('px_')).toBe(true)
		expect(rotated.apiKey).not.toBe(first.apiKey)

		// Old key is dead; new key works.
		expect((await resolveKey(h, cf, first.apiKey)).failed).toBe('invalid_key')
		expect((await resolveKey(h, cf, rotated.apiKey)).claims?.ptype).toBe('service')
	})

	test('revoke kills the native key', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const body = await provision(h, cf, token)

		const del = await run(h, cf, req(`/admin/api-keys/${body.principalId}`, 'DELETE', token))
		expect(del.status).toBe(200)
		expect((await resolveKey(h, cf, body.apiKey)).failed).toBe('invalid_key')
	})
})
