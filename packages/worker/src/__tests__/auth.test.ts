import { type AuthenticateInput, permits } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { LOCAL_DEV_ADMIN_ID, resolveRequest } from '../auth'
import { createHarness, DEFAULT_AUD, seedGrant, seedProject, seedUser } from './helpers/harness'

// FINDING TEST-1 (SEC-1): the local dev-bypass guard in resolveRequest. There is no
// Cloudflare Access in front of `lopata`/`wrangler dev`, so the Worker resolves a
// fixed global-admin identity when ENVIRONMENT='local' AND no token is presented AND
// no Access is configured (ACCESS_APPS empty). Every one of those preconditions is a
// security boundary: this drives resolveRequest end to end (real JwtValidator, real
// Db over bun:sqlite) and proves the bypass fires ONLY for that exact combination —
// and that a real token is never hijacked by it even on local.

// A bare AuthenticateInput; tests override `token` per case.
function input(overrides: Partial<AuthenticateInput> = {}): AuthenticateInput {
	return {
		app: 'iam-admin',
		token: null,
		cookie: null,
		origin: null,
		requestId: 'req-1',
		...overrides,
	}
}

describe('resolveRequest — local dev bypass (SEC-1 guard)', () => {
	test('local + no token + empty ACCESS_APPS → bypass fires: global-admin bootstrap principal', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'local', accessApps: {} })

		const outcome = await resolveRequest(services, input({ token: null }))

		expect(outcome.result.ok).toBe(true)
		if (!outcome.result.ok) throw new Error('expected ok')
		expect(outcome.result.principal.id).toBe(LOCAL_DEV_ADMIN_ID)
		expect(outcome.result.principal.permissions).toEqual([{ action: '*', projectId: null, source: 'bootstrap' }])
		expect(outcome.logReason).toBe('local_bypass')
	})

	test('local + no token + NON-empty ACCESS_APPS → bypass does NOT fire → missing_token', async () => {
		// The defense-in-depth precondition: any real Access deploy has a non-empty
		// audience map, so even a mis-pinned ENVIRONMENT=local cannot unlock admin.
		const h = createHarness()
		const services = h.makeServices({ environment: 'local', accessApps: { aud: 'app' } })

		const outcome = await resolveRequest(services, input({ token: null }))

		expect(outcome.result.ok).toBe(false)
		if (outcome.result.ok) throw new Error('expected failure')
		expect(outcome.result.reason).toBe('missing_token')
	})

	test('stage + no token → bypass does NOT fire (environment gate) → missing_token', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage', accessApps: {} })

		const outcome = await resolveRequest(services, input({ token: null }))

		expect(outcome.result.ok).toBe(false)
		if (outcome.result.ok) throw new Error('expected failure')
		expect(outcome.result.reason).toBe('missing_token')
	})

	test('local + a VALID user token → real grants win, bypass never hijacks the token', async () => {
		// Even on local, a presented token validates normally: the bypass requires
		// token === null. A user with only a project-scoped `viewer` grant must
		// resolve to that grant's permissions, NOT the global-admin bootstrap.
		const h = createHarness()
		const projectId = seedProject(h.sqlite, 'alpha')
		const principalId = seedUser(h.sqlite, { sub: 'sub-alice', email: 'alice@example.com' })
		seedGrant(h.sqlite, principalId, 'viewer', projectId)

		// ACCESS_APPS must be non-empty for jose to accept the token's aud — but that
		// also means the no-token bypass precondition is off, which is the real shape
		// of any deploy that actually validates tokens.
		const services = h.makeServices({ environment: 'local', accessApps: { [DEFAULT_AUD]: 'iam-admin' } })
		const token = await h.signToken({ email: 'alice@example.com', sub: 'sub-alice' })

		const outcome = await resolveRequest(services, input({ token }))

		expect(outcome.result.ok).toBe(true)
		if (!outcome.result.ok) throw new Error('expected ok')
		// The real principal, not the bypass identity.
		expect(outcome.result.principal.id).toBe(principalId)
		expect(outcome.result.principal.id).not.toBe(LOCAL_DEV_ADMIN_ID)
		// viewer → project.read + report.read, scoped to the project, source 'grant'.
		expect(outcome.result.principal.permissions).toEqual([
			{ action: 'project.read', projectId, source: 'grant' },
			{ action: 'report.read', projectId, source: 'grant' },
		])
		// No global-admin `*` leaked in from the bypass.
		expect(outcome.result.principal.permissions.some((p) => p.action === '*')).toBe(false)
		expect(outcome.logReason).not.toBe('local_bypass')
	})
})

// The cross-app isolation contract: a grant carries an `app` dimension and
// authenticate() filters a principal's permissions to the aud-verified calling app
// (or NULL = cross-app). A grant for one app must never confer permissions in another.
describe('resolveRequest — app-scoped grants (cross-app isolation)', () => {
	test('grants for OTHER apps do not apply; calling-app + cross-app (NULL) grants do', async () => {
		const h = createHarness()
		const principalId = seedUser(h.sqlite, { sub: 'sub-bob', email: 'bob@example.com' })
		// DEFAULT_AUD → 'iam-admin', the verified app for the default signed token.
		seedGrant(h.sqlite, principalId, 'editor', null, 'iam-admin') // applies (same app)
		seedGrant(h.sqlite, principalId, 'admin', null, 'other-app') // must NOT apply (different app)
		seedGrant(h.sqlite, principalId, 'viewer', null, null) // applies (cross-app)

		const services = h.makeServices({ environment: 'stage', accessApps: { [DEFAULT_AUD]: 'iam-admin' } })
		const token = await h.signToken({ email: 'bob@example.com', sub: 'sub-bob' })
		const outcome = await resolveRequest(services, input({ token }))

		expect(outcome.result.ok).toBe(true)
		if (!outcome.result.ok) throw new Error('expected ok')
		const perms = outcome.result.principal.permissions
		expect(permits(perms, 'project.write')).toBe(true) // editor@iam-admin applied
		expect(permits(perms, 'report.read')).toBe(true) // viewer (cross-app) applied
		expect(permits(perms, 'iam.admin')).toBe(false) // admin@other-app did NOT leak across apps
	})

	test('authenticating as a DIFFERENT app drops the other-app grant, keeps only cross-app', async () => {
		const h = createHarness()
		const principalId = seedUser(h.sqlite, { sub: 'sub-carol', email: 'carol@example.com' })
		seedGrant(h.sqlite, principalId, 'admin', null, 'iam-admin') // admin ONLY for iam-admin
		seedGrant(h.sqlite, principalId, 'viewer', null, null) // cross-app viewer

		// The token's aud maps to 'poplach', not 'iam-admin'.
		const services = h.makeServices({ environment: 'stage', accessApps: { 'aud-poplach': 'poplach' } })
		const token = await h.signToken({ email: 'carol@example.com', sub: 'sub-carol' }, { audience: 'aud-poplach' })
		const outcome = await resolveRequest(services, input({ token }))

		expect(outcome.result.ok).toBe(true)
		if (!outcome.result.ok) throw new Error('expected ok')
		const perms = outcome.result.principal.permissions
		expect(permits(perms, 'iam.admin')).toBe(false) // admin@iam-admin did NOT apply as poplach
		expect(permits(perms, 'project.read')).toBe(true) // cross-app viewer applied
		expect(permits(perms, 'project.write')).toBe(false) // and nothing editor/admin-level
	})
})
