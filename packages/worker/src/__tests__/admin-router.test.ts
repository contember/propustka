import { describe, expect, test } from 'bun:test'
import { handleAdmin } from '../admin/router'
import type { Env } from '../env'
import type { Services } from '../services'
import { createHarness, type Harness, seedGrant, seedRole, seedUser } from './helpers/harness'

// FINDING TEST-2: the admin gate wiring in handleAdmin. Every /admin/* request must
// pass a scope-less can('iam.admin') check — satisfied ONLY by a GLOBAL `admin`
// grant (or bootstrap), NEVER by a project-scoped one. This drives handleAdmin end
// to end with a real propustka-native SSO session (`px_session` cookie → real Db over
// bun:sqlite) and asserts the HTTP status, covering the core security property plus the
// missing/invalid/disabled mapping and the SEC-2 same-origin CSRF guard.

const ORIGIN = 'https://iam.example.com'

// The admin app id every native session is resolved against (see admin/router.ts).
const IAM_APP = 'propustka'

// env slice handleAdmin needs. ENVIRONMENT='stage' keeps the local-dev bypass off, so the
// session/credential paths are exercised for real.
const ADMIN_ENV: Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'> = { PROPUSTKA_SIGNING_KEYS: '', ENVIRONMENT: 'stage' }

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
	/** Plaintext `px_session` cookie value (a native SSO session). */
	session?: string | null
	/** Origin header to send (defaults to same-origin ORIGIN for state-changing methods). */
	origin?: string | null
}

function adminRequest(path: string, opts: RequestOptions = {}): Request {
	const headers = new Headers()
	if (opts.session) {
		headers.set('Cookie', `px_session=${opts.session}`)
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

// Services in 'stage' so the local-dev bypass precondition is off (the session path runs for real).
function adminServices(h: Harness): Services {
	return h.makeServices({ environment: 'stage' })
}

async function run(h: Harness, request: Request): Promise<Response> {
	return handleAdmin(request, adminServices(h), ADMIN_ENV, new FakeExecutionContext())
}

describe('handleAdmin — admin gate (scope-less iam.admin)', () => {
	test('GLOBAL admin grant → 200 (passes the gate)', async () => {
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-admin', email: 'admin@example.com' })
		seedGrant(h.sqlite, id, 'admin', null) // global

		const session = await h.signSession(id)
		const res = await run(h, adminRequest('/admin/roles', { session }))

		expect(res.status).toBe(200)
	})

	test('SCOPE-BOUND admin grant → 403 (scope-less iam.admin is not satisfied by a scoped entry)', async () => {
		// The core security property: an `admin` grant pinned to one scope value must
		// NOT confer the global admin capability.
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-scoped', email: 'scoped@example.com' })
		seedGrant(h.sqlite, id, 'admin', { type: 'team', value: 'acme' }) // scope-bound

		const session = await h.signSession(id)
		const res = await run(h, adminRequest('/admin/roles', { session }))

		expect(res.status).toBe(403)
	})

	test('only a viewer grant → 403', async () => {
		const h = createHarness()
		seedRole(h.sqlite, IAM_APP, 'viewer', ['project.read'])
		const id = seedUser(h.sqlite, { sub: 'sub-viewer', email: 'viewer@example.com' })
		seedGrant(h.sqlite, id, 'viewer', null, IAM_APP)

		const session = await h.signSession(id)
		const res = await run(h, adminRequest('/admin/roles', { session }))

		expect(res.status).toBe(403)
	})

	test('no session → 401 (missing_token)', async () => {
		const h = createHarness()
		const res = await run(h, adminRequest('/admin/roles'))

		expect(res.status).toBe(401)
	})

	test('invalid (unknown) session → 401', async () => {
		const h = createHarness()
		const res = await run(h, adminRequest('/admin/roles', { session: 'sess-does-not-exist' }))

		expect(res.status).toBe(401)
	})

	test('disabled principal with a global admin grant → 403 (disabled)', async () => {
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-disabled', email: 'disabled@example.com', disabled: true })
		seedGrant(h.sqlite, id, 'admin', null)

		const session = await h.signSession(id)
		const res = await run(h, adminRequest('/admin/roles', { session }))

		expect(res.status).toBe(403)
	})

	test('GET /admin/me with a global admin grant → 200 (gate also fronts /me)', async () => {
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-me', email: 'me@example.com' })
		seedGrant(h.sqlite, id, 'admin', null)

		const session = await h.signSession(id)
		const res = await run(h, adminRequest('/admin/me', { session }))

		expect(res.status).toBe(200)
	})
})

describe('handleAdmin — same-origin CSRF guard (SEC-2)', () => {
	test('cross-origin state-changing POST → 403 BEFORE the gate (even for a global admin)', async () => {
		// The CSRF check runs before the caller is resolved, so a valid admin session does not
		// rescue a cross-origin write.
		const h = createHarness()
		const id = seedUser(h.sqlite, { sub: 'sub-admin2', email: 'admin2@example.com' })
		seedGrant(h.sqlite, id, 'admin', null)

		const session = await h.signSession(id)
		const res = await run(
			h,
			adminRequest('/admin/grants', { method: 'POST', session, origin: 'https://evil.example.com' }),
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
		seedRole(h.sqlite, IAM_APP, 'viewer', ['project.read'])
		const id = seedUser(h.sqlite, { sub: 'sub-v2', email: 'v2@example.com' })
		seedGrant(h.sqlite, id, 'viewer', null, IAM_APP)

		const session = await h.signSession(id)
		const res = await run(h, adminRequest('/admin/grants', { method: 'POST', session, origin: ORIGIN }))

		expect(res.status).toBe(403)
		const body: unknown = await res.json()
		expect(body).toEqual({ error: 'admin permission required' })
	})
})
