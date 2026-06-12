import { describe, expect, test } from 'bun:test'
import { handleAdmin } from '../admin/router'
import type { Services } from '../services'
import { createHarness, DEFAULT_AUD, type Harness, seedGrant, seedRole, seedUser } from './helpers/harness'

// FINDING TEST-2: the admin gate wiring in handleAdmin. Every /admin/* request must
// pass a scope-less can('iam.admin') check — satisfied ONLY by a GLOBAL `admin`
// grant (or bootstrap), NEVER by a project-scoped one. This drives handleAdmin end
// to end with real signed tokens in the Cf-Access-Jwt-Assertion header (real
// JwtValidator + real Db over bun:sqlite) and asserts the HTTP status, covering the
// core security property plus the missing/invalid/disabled mapping and the SEC-2
// same-origin CSRF guard on state-changing requests.

const ORIGIN = 'https://iam.example.com'

// A minimal ExecutionContext. `handleAdmin` only ever calls ctx.waitUntil /
// passThroughOnException (via handlers); we record waitUntil promises but never
// need them here, since the gate decisions assert on the response status alone.
class FakeExecutionContext implements ExecutionContext {
	readonly props: unknown = undefined
	readonly pending: Promise<unknown>[] = []

	waitUntil(promise: Promise<unknown>): void {
		this.pending.push(promise)
	}

	passThroughOnException(): void {}
}

interface RequestOptions {
	method?: string
	token?: string | null
	/** Origin header to send (defaults to same-origin ORIGIN for state-changing methods). */
	origin?: string | null
}

function adminRequest(path: string, opts: RequestOptions = {}): Request {
	const headers = new Headers()
	if (opts.token) {
		headers.set('Cf-Access-Jwt-Assertion', opts.token)
	}
	const method = opts.method ?? 'GET'
	const stateChanging = method === 'POST' || method === 'PATCH' || method === 'DELETE'
	// Default state-changing requests to same-origin so they clear the CSRF guard and
	// reach the gate (unless a test overrides `origin` to probe the guard itself).
	const origin = opts.origin === undefined ? (stateChanging ? ORIGIN : null) : opts.origin
	if (origin !== null) {
		headers.set('Origin', origin)
	}
	return new Request(`${ORIGIN}${path}`, { method, headers })
}

// Services configured with real Access (non-empty ACCESS_APPS) so signed tokens
// verify and the local-dev bypass precondition is off.
function adminServices(h: Harness): Services {
	return h.makeServices({ environment: 'stage', accessApps: { [DEFAULT_AUD]: 'iam-admin' } })
}

async function run(h: Harness, request: Request): Promise<Response> {
	return handleAdmin(request, adminServices(h), new FakeExecutionContext())
}

describe('handleAdmin — admin gate (scope-less iam.admin)', () => {
	test('GLOBAL admin grant → 200 (passes the gate)', async () => {
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-admin', email: 'admin@example.com' })
		seedGrant(h.sqlite, id, 'admin', null) // global

		const token = await h.signToken({ email: 'admin@example.com', sub: 'sub-admin' })
		const res = await run(h, adminRequest('/admin/roles', { token }))

		expect(res.status).toBe(200)
	})

	test('SCOPE-BOUND admin grant → 403 (scope-less iam.admin is not satisfied by a scoped entry)', async () => {
		// The core security property: an `admin` grant pinned to one scope value must
		// NOT confer the global admin capability.
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-scoped', email: 'scoped@example.com' })
		seedGrant(h.sqlite, id, 'admin', { type: 'team', value: 'acme' }) // scope-bound

		const token = await h.signToken({ email: 'scoped@example.com', sub: 'sub-scoped' })
		const res = await run(h, adminRequest('/admin/roles', { token }))

		expect(res.status).toBe(403)
	})

	test('only a viewer grant → 403', async () => {
		const h = createHarness()
		seedRole(h.sqlite, 'iam-admin', 'viewer', ['project.read'])
		const id = seedUser(h.sqlite, { sub: 'sub-viewer', email: 'viewer@example.com' })
		seedGrant(h.sqlite, id, 'viewer', null, 'iam-admin')

		const token = await h.signToken({ email: 'viewer@example.com', sub: 'sub-viewer' })
		const res = await run(h, adminRequest('/admin/roles', { token }))

		expect(res.status).toBe(403)
	})

	test('no token → 401 (missing_token)', async () => {
		const h = createHarness()
		const res = await run(h, adminRequest('/admin/roles'))

		expect(res.status).toBe(401)
	})

	test('disabled principal with a global admin grant → 403 (disabled)', async () => {
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-disabled', email: 'disabled@example.com', disabled: true })
		seedGrant(h.sqlite, id, 'admin', null)

		const token = await h.signToken({ email: 'disabled@example.com', sub: 'sub-disabled' })
		const res = await run(h, adminRequest('/admin/roles', { token }))

		expect(res.status).toBe(403)
	})

	test('GET /admin/me with a global admin grant → 200 (gate also fronts /me)', async () => {
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-me', email: 'me@example.com' })
		seedGrant(h.sqlite, id, 'admin', null)

		const token = await h.signToken({ email: 'me@example.com', sub: 'sub-me' })
		const res = await run(h, adminRequest('/admin/me', { token }))

		expect(res.status).toBe(200)
	})
})

describe('handleAdmin — same-origin CSRF guard (SEC-2)', () => {
	test('cross-origin state-changing POST → 403 BEFORE the gate (even for a global admin)', async () => {
		// The CSRF check runs before resolveRequest, so a valid admin token does not
		// rescue a cross-origin write.
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-admin2', email: 'admin2@example.com' })
		seedGrant(h.sqlite, id, 'admin', null)

		const token = await h.signToken({ email: 'admin2@example.com', sub: 'sub-admin2' })
		const res = await run(
			h,
			adminRequest('/admin/grants', { method: 'POST', token, origin: 'https://evil.example.com' }),
		)

		expect(res.status).toBe(403)
		const body: unknown = await res.json()
		expect(body).toEqual({ error: 'cross-origin request rejected' })
	})

	test('same-origin state-changing POST is NOT blocked by the CSRF guard (reaches the gate)', async () => {
		// A same-origin POST from a non-admin clears the CSRF guard and is rejected by
		// the gate instead (403 'admin permission required'), proving the guard let it
		// through rather than blocking on origin.
		const h = createHarness()
		seedRole(h.sqlite, 'iam-admin', 'viewer', ['project.read'])
		const id = seedUser(h.sqlite, { sub: 'sub-v2', email: 'v2@example.com' })
		seedGrant(h.sqlite, id, 'viewer', null, 'iam-admin')

		const token = await h.signToken({ email: 'v2@example.com', sub: 'sub-v2' })
		const res = await run(h, adminRequest('/admin/grants', { method: 'POST', token, origin: ORIGIN }))

		expect(res.status).toBe(403)
		const body: unknown = await res.json()
		expect(body).toEqual({ error: 'admin permission required' })
	})
})
