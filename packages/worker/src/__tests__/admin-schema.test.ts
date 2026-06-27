import { describe, expect, test } from 'bun:test'
import { handleAdmin } from '../admin/router'
import type { AppSchemaDto, GrantDto, PolicyDto, RoleDto } from '../admin/types'
import type { Env } from '../env'
import type { Services } from '../services'
import { createHarness, type Harness, seedAppAction, seedGrant, seedUser } from './helpers/harness'

const ADMIN_ENV: Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'PROPUSTKA_PROVISIONING_KEY' | 'ENVIRONMENT'> = {
	PROPUSTKA_SIGNING_KEYS: '',
	PROPUSTKA_PROVISIONING_KEY: '',
	ENVIRONMENT: 'stage',
}

// End-to-end admin tests for the NEW surfaces introduced by the generic-scopes refactor:
//   - PUT/GET /admin/apps/:app/schema   — idempotent vocabulary reconcile + readback;
//   - custom policies survive a re-reconcile;
//   - action-catalog validation rejects unknown actions on schema + policy + grant;
//   - grant create enforces role XOR inline, validates inline against the catalog, and
//     enforces both-or-neither scope.
// Driven through `handleAdmin` with a real native admin session (`px_session` cookie + real
// Db over bun:sqlite), exactly like admin-router.test.ts.

const ORIGIN = 'https://iam.example.com'

class FakeExecutionContext implements ExecutionContext {
	readonly props: unknown = undefined
	readonly pending: Promise<unknown>[] = []
	waitUntil(promise: Promise<unknown>): void {
		this.pending.push(promise)
	}
	passThroughOnException(): void {}
}

// The target app ('opice') registers itself by reconciling its schema (`PUT …/opice/schema`), which
// is how it lands in the DB-derived `knownApps` registry — no static config list anymore.
function adminServices(h: Harness): Services {
	return h.makeServices({ environment: 'stage' })
}

// Seed a global admin user and open an SSO session so every request clears the gate.
async function asAdmin(h: Harness): Promise<string> {
	const id = seedUser(h.sqlite, { sub: 'sub-admin', email: 'admin@example.com' })
	seedGrant(h.sqlite, id, 'admin', null) // built-in admin, global, cross-app
	return h.signSession(id)
}

function req(path: string, method: string, session: string, body?: unknown): Request {
	const headers = new Headers({ Cookie: `px_session=${session}` })
	const stateChanging = method !== 'GET'
	if (stateChanging) {
		headers.set('Origin', ORIGIN)
		headers.set('Content-Type', 'application/json')
	}
	return new Request(`${ORIGIN}${path}`, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) })
}

async function run(h: Harness, request: Request): Promise<Response> {
	return handleAdmin(request, adminServices(h), ADMIN_ENV, new FakeExecutionContext())
}

const SCHEMA = {
	scopes: [{ type: 'organization', label: 'Organization' }, { type: 'team' }],
	actions: [
		{ action: 'project.read', description: 'Read' },
		{ action: 'project.write' },
		{ action: 'report.export' },
	],
	roles: {
		editor: { name: 'Editor', permissions: ['project.read', 'project.write'] },
		viewer: { name: 'Viewer', permissions: ['project.read'] },
	},
}

describe('PUT/GET /admin/apps/:app/schema', () => {
	test('reconciles the vocabulary and reads it back', async () => {
		const h = createHarness()
		const token = await asAdmin(h)

		const put = await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		expect(put.status).toBe(200)

		const get = await run(h, req('/admin/apps/opice/schema', 'GET', token))
		expect(get.status).toBe(200)
		const dto: AppSchemaDto = await get.json()
		expect(dto.app).toBe('opice')
		expect(dto.scopes.map((s) => s.type)).toEqual(['organization', 'team'])
		expect(dto.actions.map((a) => a.action)).toEqual(['project.read', 'project.write', 'report.export'])
		expect(Object.keys(dto.roles).sort()).toEqual(['editor', 'viewer'])
		expect(dto.roles['editor']?.permissions).toEqual(['project.read', 'project.write'])
	})

	test('rejects a schema whose role references an unknown action (400)', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		const bad = {
			scopes: [],
			actions: [{ action: 'project.read' }],
			roles: { editor: { name: 'Editor', permissions: ['project.delete'] } }, // project.delete not in catalog
		}
		const res = await run(h, req('/admin/apps/opice/schema', 'PUT', token, bad))
		expect(res.status).toBe(400)
		const body: { error: string } = await res.json()
		expect(body.error).toContain('project.delete')
	})

	test('a prefix wildcard is valid iff the namespace is non-empty', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		// 'report.*' is allowed because the catalog has 'report.export' under it.
		const ok = await run(
			h,
			req('/admin/apps/opice/schema', 'PUT', token, {
				scopes: [],
				actions: [{ action: 'report.export' }],
				roles: { exporter: { name: 'Exporter', permissions: ['report.*'] } },
			}),
		)
		expect(ok.status).toBe(200)
		// 'ghost.*' is rejected — no catalog action under that namespace.
		const bad = await run(
			h,
			req('/admin/apps/opice/schema', 'PUT', token, {
				scopes: [],
				actions: [{ action: 'report.export' }],
				roles: { ghost: { name: 'Ghost', permissions: ['ghost.*'] } },
			}),
		)
		expect(bad.status).toBe(400)
	})

	test('reconcile preserves custom policies and prunes absent app roles', async () => {
		const h = createHarness()
		const token = await asAdmin(h)

		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))

		// Compose a custom policy.
		const created = await run(
			h,
			req('/admin/apps/opice/policies', 'POST', token, {
				key: 'auditor',
				name: 'Auditor',
				permissions: ['project.read', 'report.export'],
			}),
		)
		expect(created.status).toBe(201)

		// Re-reconcile WITHOUT 'editor' (drops it) — and keep 'viewer'.
		await run(
			h,
			req('/admin/apps/opice/schema', 'PUT', token, {
				...SCHEMA,
				roles: { viewer: { name: 'Viewer', permissions: ['project.read'] } },
			}),
		)

		const schema: AppSchemaDto = await (await run(h, req('/admin/apps/opice/schema', 'GET', token))).json()
		expect(Object.keys(schema.roles)).toEqual(['viewer']) // editor pruned

		// The custom policy is untouched.
		const policies: { items: PolicyDto[] } = await (await run(h, req('/admin/apps/opice/policies', 'GET', token))).json()
		expect(policies.items.map((p) => p.key)).toEqual(['auditor'])
		expect(policies.items[0]?.permissions).toEqual(['project.read', 'report.export'])
	})

	test('a not-yet-registered app reconciles its schema (first reconcile = registration)', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		const res = await run(h, req('/admin/apps/newapp/schema', 'PUT', token, SCHEMA))
		expect(res.status).toBe(200)
	})
})

describe('policy CRUD validates against the action catalog', () => {
	test('create rejects an unknown action pattern (400); update + delete work', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))

		const bad = await run(
			h,
			req('/admin/apps/opice/policies', 'POST', token, { key: 'p1', name: 'P1', permissions: ['nope.read'] }),
		)
		expect(bad.status).toBe(400)

		const ok = await run(
			h,
			req('/admin/apps/opice/policies', 'POST', token, { key: 'p1', name: 'P1', permissions: ['project.read'] }),
		)
		expect(ok.status).toBe(201)

		// Update broadens the policy; validated against the catalog again.
		const upd = await run(
			h,
			req('/admin/apps/opice/policies/p1', 'PUT', token, { name: 'P1', permissions: ['project.read', 'project.write'] }),
		)
		expect(upd.status).toBe(200)
		const updated: PolicyDto = await upd.json()
		expect(updated.permissions).toEqual(['project.read', 'project.write'])

		const del = await run(h, req('/admin/apps/opice/policies/p1', 'DELETE', token))
		expect(del.status).toBe(200)
		const list: { items: PolicyDto[] } = await (await run(h, req('/admin/apps/opice/policies', 'GET', token))).json()
		expect(list.items).toHaveLength(0)
	})

	test('a policy cannot reuse the reserved built-in `admin` key', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		const res = await run(
			h,
			req('/admin/apps/opice/policies', 'POST', token, { key: 'admin', name: 'X', permissions: ['project.read'] }),
		)
		expect(res.status).toBe(400)
	})

	test('cannot update or delete an origin=app role via the policy endpoints', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		// 'editor' is an origin='app' role — the policy endpoints only manage 'custom'.
		const upd = await run(
			h,
			req('/admin/apps/opice/policies/editor', 'PUT', token, { name: 'Editor', permissions: ['project.read'] }),
		)
		expect(upd.status).toBe(404)
		const del = await run(h, req('/admin/apps/opice/policies/editor', 'DELETE', token))
		expect(del.status).toBe(404)
	})
})

describe('grant create — role XOR inline, catalog validation, scope both-or-neither', () => {
	async function targetPrincipal(h: Harness): Promise<string> {
		return seedUser(h.sqlite, { sub: 'sub-target', email: 'target@example.com' })
	}

	// Register 'opice' in the DB-derived app registry (so `appField`/`knownApps` accept it) without a
	// full schema reconcile — for the tests below that grant against 'opice' but don't PUT its schema.
	function registerOpice(h: Harness): void {
		seedAppAction(h.sqlite, 'opice', 'report.read')
	}

	test('a role grant against an app role succeeds and reflects the role', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		const principalId = await targetPrincipal(h)

		const res = await run(
			h,
			req('/admin/grants', 'POST', token, { principalId, app: 'opice', roleKey: 'editor' }),
		)
		expect(res.status).toBe(201)
		const grant: GrantDto = await res.json()
		expect(grant.roleKey).toBe('editor')
		expect(grant.permissions).toBeNull()
		expect(grant.dangling).toBe(false)
	})

	test('the built-in admin role is grantable for any app', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		registerOpice(h)
		const principalId = await targetPrincipal(h)
		const res = await run(h, req('/admin/grants', 'POST', token, { principalId, app: 'opice', roleKey: 'admin' }))
		expect(res.status).toBe(201)
	})

	test('an unknown role is rejected (400)', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		registerOpice(h)
		const principalId = await targetPrincipal(h)
		const res = await run(h, req('/admin/grants', 'POST', token, { principalId, app: 'opice', roleKey: 'ghost' }))
		expect(res.status).toBe(400)
	})

	test('an inline grant validates each pattern against the app catalog', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		const principalId = await targetPrincipal(h)

		const ok = await run(
			h,
			req('/admin/grants', 'POST', token, { principalId, app: 'opice', permissions: ['report.export'] }),
		)
		expect(ok.status).toBe(201)
		const grant: GrantDto = await ok.json()
		expect(grant.roleKey).toBeNull()
		expect(grant.permissions).toEqual(['report.export'])

		const bad = await run(
			h,
			req('/admin/grants', 'POST', token, { principalId, app: 'opice', permissions: ['project.delete'] }),
		)
		expect(bad.status).toBe(400)
	})

	test('supplying BOTH roleKey and permissions is rejected (XOR)', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		const principalId = await targetPrincipal(h)
		const res = await run(
			h,
			req('/admin/grants', 'POST', token, { principalId, app: 'opice', roleKey: 'editor', permissions: ['report.export'] }),
		)
		expect(res.status).toBe(400)
	})

	test('supplying NEITHER roleKey nor permissions is rejected (XOR)', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		registerOpice(h)
		const principalId = await targetPrincipal(h)
		const res = await run(h, req('/admin/grants', 'POST', token, { principalId, app: 'opice' }))
		expect(res.status).toBe(400)
	})

	test('a half-set scope (scopeType without scopeValue) is rejected (400)', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		registerOpice(h)
		const principalId = await targetPrincipal(h)
		const res = await run(
			h,
			req('/admin/grants', 'POST', token, { principalId, app: 'opice', roleKey: 'admin', scopeType: 'team' }),
		)
		expect(res.status).toBe(400)
	})

	test('a full scope coordinate is accepted and reflected', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		registerOpice(h)
		const principalId = await targetPrincipal(h)
		const res = await run(
			h,
			req('/admin/grants', 'POST', token, {
				principalId,
				app: 'opice',
				roleKey: 'admin',
				scopeType: 'team',
				scopeValue: 'acme',
			}),
		)
		expect(res.status).toBe(201)
		const grant: GrantDto = await res.json()
		expect(grant.scopeType).toBe('team')
		expect(grant.scopeValue).toBe('acme')
	})
})

describe('GET /admin/roles is app-aware (built-ins + the app DB roles)', () => {
	test('lists built-in admin plus the app roles for ?app=opice', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		await run(h, req('/admin/apps/opice/schema', 'PUT', token, SCHEMA))
		const res = await run(h, req('/admin/roles?app=opice', 'GET', token))
		expect(res.status).toBe(200)
		const body: { items: RoleDto[] } = await res.json()
		const byKey = new Map(body.items.map((r) => [r.key, r]))
		expect(byKey.get('admin')?.origin).toBe('builtin')
		expect(byKey.get('editor')?.origin).toBe('app')
		expect(byKey.get('viewer')?.origin).toBe('app')
	})

	test('without ?app only the built-ins are listed', async () => {
		const h = createHarness()
		const token = await asAdmin(h)
		const res = await run(h, req('/admin/roles', 'GET', token))
		const body: { items: RoleDto[] } = await res.json()
		expect(body.items.map((r) => r.key)).toEqual(['admin'])
	})
})
