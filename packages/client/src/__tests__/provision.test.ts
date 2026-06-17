import type { AppAccess } from '@propustka/core'
import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import { reconcileAccess, ReconcileAccessError } from '../provision'

// reconcileAccess goes over the global fetch (HTTP to the admin origin). We spy on fetch, capture
// the outgoing request, and drive the response status — no network, no `as` casts.

const ACCESS: AppAccess = {
	apps: [
		{
			key: 'operator',
			name: 'opice-operator',
			destinations: ['opice.example.com'],
			rules: [{ kind: 'service-auth' }, { kind: 'human', emailDomains: ['contember.com'] }],
		},
	],
}

// One captured outgoing fetch call → its url + parsed request shape.
function captured(spy: ReturnType<typeof stubFetch>): { url: string; method: string | undefined; headers: Headers; body: unknown } {
	const call = spy.mock.calls[0]
	if (!call) {
		throw new Error('fetch was not called')
	}
	const [input, init] = call
	return {
		url: String(input),
		method: init?.method,
		headers: new Headers(init?.headers),
		body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
	}
}

let restore: (() => void) | undefined

function stubFetch(status: number, body: unknown = {}) {
	const spy = spyOn(globalThis, 'fetch').mockResolvedValue(
		new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }),
	)
	restore = () => spy.mockRestore()
	return spy
}

afterEach(() => {
	restore?.()
	restore = undefined
})

describe('reconcileAccess', () => {
	test('PUTs the declaration to /admin/apps/:app/access (trailing slash trimmed)', async () => {
		const spy = stubFetch(200)
		await reconcileAccess({ url: 'https://propustka.example.com/', app: 'opice', access: ACCESS })
		expect(spy.mock.calls).toHaveLength(1)
		const req = captured(spy)
		expect(req.url).toBe('https://propustka.example.com/admin/apps/opice/access')
		expect(req.method).toBe('PUT')
		expect(req.body).toEqual(ACCESS)
	})

	test('forwards the Access service-token headers when provided', async () => {
		const spy = stubFetch(200)
		await reconcileAccess({ url: 'https://propustka.example.com', app: 'opice', access: ACCESS, accessClientId: 'cid', accessClientSecret: 'sec' })
		const req = captured(spy)
		expect(req.headers.get('CF-Access-Client-Id')).toBe('cid')
		expect(req.headers.get('CF-Access-Client-Secret')).toBe('sec')
	})

	test('a non-2xx response throws ReconcileAccessError carrying status + message', async () => {
		stubFetch(502, { error: 'cloudflare said no' })
		const err = await reconcileAccess({ url: 'https://propustka.example.com', app: 'opice', access: ACCESS }).catch((e: unknown) => e)
		expect(err).toBeInstanceOf(ReconcileAccessError)
		if (err instanceof ReconcileAccessError) {
			expect(err.status).toBe(502)
			expect(err.message).toContain('cloudflare said no')
		}
	})

	test('a half-set service token throws BEFORE any request', async () => {
		const spy = stubFetch(200)
		await expect(reconcileAccess({ url: 'https://propustka.example.com', app: 'opice', access: ACCESS, accessClientId: 'cid' })).rejects.toThrow()
		expect(spy.mock.calls).toHaveLength(0)
	})
})
