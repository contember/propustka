import type { AppSchema } from '@propustka/core'
import { afterEach, describe, expect, spyOn, test } from 'bun:test'
import { reconcileSchema, ReconcileSchemaError } from '../provision'

// reconcileSchema goes over the global fetch (HTTP to the admin origin). We spy on fetch, capture
// the outgoing request, and drive the response status — no network, no `as` casts.

const SCHEMA: AppSchema = {
	scopes: [{ type: 'project', label: 'Project' }],
	actions: [{ action: 'report.read', description: 'Read reports' }],
	roles: { viewer: { name: 'Viewer', permissions: ['report.read'] } },
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

describe('reconcileSchema', () => {
	test('PUTs the declaration to /admin/apps/:app/schema (trailing slash trimmed)', async () => {
		const spy = stubFetch(200)
		await reconcileSchema({ url: 'https://propustka.example.com/', app: 'opice', schema: SCHEMA })
		expect(spy.mock.calls).toHaveLength(1)
		const req = captured(spy)
		expect(req.url).toBe('https://propustka.example.com/admin/apps/opice/schema')
		expect(req.method).toBe('PUT')
		expect(req.body).toEqual(SCHEMA)
	})

	test('forwards the admin auth headers when provided', async () => {
		const spy = stubFetch(200)
		await reconcileSchema({ url: 'https://propustka.example.com', app: 'opice', schema: SCHEMA, accessClientId: 'cid', accessClientSecret: 'sec' })
		const req = captured(spy)
		expect(req.headers.get('CF-Access-Client-Id')).toBe('cid')
		expect(req.headers.get('CF-Access-Client-Secret')).toBe('sec')
	})

	test('a non-2xx response throws ReconcileSchemaError carrying status + message', async () => {
		stubFetch(502, { error: 'admin said no' })
		const err = await reconcileSchema({ url: 'https://propustka.example.com', app: 'opice', schema: SCHEMA }).catch((e: unknown) => e)
		expect(err).toBeInstanceOf(ReconcileSchemaError)
		if (err instanceof ReconcileSchemaError) {
			expect(err.status).toBe(502)
			expect(err.message).toContain('admin said no')
		}
	})

	test('a half-set credential throws BEFORE any request', async () => {
		const spy = stubFetch(200)
		await expect(reconcileSchema({ url: 'https://propustka.example.com', app: 'opice', schema: SCHEMA, accessClientId: 'cid' })).rejects.toThrow()
		expect(spy.mock.calls).toHaveLength(0)
	})
})
