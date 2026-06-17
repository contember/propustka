import { describe, expect, test } from 'bun:test'
import { handleAdmin } from '../admin/router'
import type { AppAccessDto, AuditEventDto } from '../admin/types'
import type { Services } from '../services'
import { FakeCfAccess } from './helpers/fake-cfaccess'
import { createHarness, DEFAULT_AUD, type Harness, seedGrant, seedUser } from './helpers/harness'

// End-to-end admin tests for PUT/GET /admin/apps/:app/access — the Cloudflare Access edge-rules
// reconcile. Driven through `handleAdmin` with a real signed admin token + an injected in-memory
// `FakeCfAccess` (no network), exactly like admin-schema.test.ts.

const ORIGIN = 'https://iam.example.com'

class FakeExecutionContext implements ExecutionContext {
	readonly props: unknown = undefined
	readonly pending: Promise<unknown>[] = []
	waitUntil(promise: Promise<unknown>): void {
		this.pending.push(promise)
	}
	passThroughOnException(): void {}
}

// 'opice' must be an ACCESS_APPS value for `knownApps` to accept it.
function adminServices(h: Harness, cf: FakeCfAccess): Services {
	return h.makeServices({ environment: 'stage', accessApps: { [DEFAULT_AUD]: 'iam-admin', 'aud-opice': 'opice' }, cfAccess: cf })
}

async function asAdmin(h: Harness): Promise<string> {
	const id = seedUser(h.sqlite, { sub: 'sub-admin', email: 'admin@example.com' })
	seedGrant(h.sqlite, id, 'admin', null)
	return h.signToken({ email: 'admin@example.com', sub: 'sub-admin' })
}

function req(path: string, method: string, token: string, body?: unknown, origin: string = ORIGIN): Request {
	const headers = new Headers({ 'Cf-Access-Jwt-Assertion': token })
	if (method !== 'GET') {
		headers.set('Origin', origin)
		headers.set('Content-Type', 'application/json')
	}
	return new Request(`${ORIGIN}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })
}

async function run(h: Harness, cf: FakeCfAccess, request: Request): Promise<Response> {
	return handleAdmin(request, adminServices(h, cf), new FakeExecutionContext())
}

const ACCESS = {
	apps: [
		{
			key: 'operator',
			name: 'opice-operator',
			destinations: ['opice.example.com'],
			rules: [{ kind: 'service-auth' }, { kind: 'human', emailDomains: ['contember.com'] }],
		},
		{ key: 'public', name: 'opice-public', destinations: ['opice.example.com/s'], rules: [{ kind: 'public' }] },
	],
}

describe('PUT/GET /admin/apps/:app/access', () => {
	test('reconciles the Access rules into reusable policies and reads them back', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)

		const put = await run(h, cf, req('/admin/apps/opice/access', 'PUT', token, ACCESS))
		expect(put.status).toBe(200)
		const dto: AppAccessDto = await put.json()
		expect(dto.app).toBe('opice')
		expect(dto.policies.map((p) => p.name).sort()).toEqual([
			'px:opice:operator:human',
			'px:opice:operator:service-auth',
			'px:opice:public:public',
		])

		// The reusable policies really exist in CF, and the gated app points at them.
		expect(cf.policies.size).toBe(3)
		const operator = await cf.findAppByName('opice-operator')
		expect(operator?.policyIds).toHaveLength(2)

		// GET returns the same live readback.
		const get = await run(h, cf, req('/admin/apps/opice/access', 'GET', token))
		expect(get.status).toBe(200)
		const read: AppAccessDto = await get.json()
		expect(read.policies.map((p) => `${p.key}:${p.kind}`).sort()).toEqual(dto.policies.map((p) => `${p.key}:${p.kind}`).sort())
	})

	test('writes an iam.app.access.reconcile audit event', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		await run(h, cf, req('/admin/apps/opice/access', 'PUT', token, ACCESS))

		const audit = await run(h, cf, req('/admin/audit?action=iam.app.access.reconcile', 'GET', token))
		const body: { items: AuditEventDto[] } = await audit.json()
		expect(body.items.length).toBeGreaterThan(0)
		expect(body.items[0]?.resourceId).toBe('opice')
	})

	test('empty apps → 400', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const res = await run(h, cf, req('/admin/apps/opice/access', 'PUT', token, { apps: [] }))
		expect(res.status).toBe(400)
	})

	test('a human rule with no emailDomains/emails → 400', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const res = await run(
			h,
			cf,
			req('/admin/apps/opice/access', 'PUT', token, {
				apps: [{ key: 'operator', name: 'opice-operator', destinations: ['opice.example.com'], rules: [{ kind: 'human' }] }],
			}),
		)
		expect(res.status).toBe(400)
		const body: { error: string } = await res.json()
		expect(body.error).toContain('emailDomains')
	})

	test('duplicate app keys → 400', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const res = await run(
			h,
			cf,
			req('/admin/apps/opice/access', 'PUT', token, {
				apps: [
					{ key: 'dup', name: 'a', destinations: ['a.example.com'], rules: [{ kind: 'public' }] },
					{ key: 'dup', name: 'b', destinations: ['b.example.com'], rules: [{ kind: 'public' }] },
				],
			}),
		)
		expect(res.status).toBe(400)
	})

	test('unknown :app → 404', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const res = await run(h, cf, req('/admin/apps/nope/access', 'PUT', token, ACCESS))
		expect(res.status).toBe(404)
	})

	test('a validation failure mutates nothing in Cloudflare (validate before reconcile)', async () => {
		const h = createHarness()
		const cf = new FakeCfAccess()
		const token = await asAdmin(h)
		const res = await run(
			h,
			cf,
			req('/admin/apps/opice/access', 'PUT', token, {
				apps: [{ key: 'operator', name: 'opice-operator', destinations: ['opice.example.com'], rules: [{ kind: 'human' }] }],
			}),
		)
		expect(res.status).toBe(400)
		expect(cf.policies.size).toBe(0) // rejected before any CF write
		expect(cf.apps.size).toBe(0)
	})
})
