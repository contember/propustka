import { describe, expect, test } from 'bun:test'
import { LOCAL_DEV_ADMIN_ID, PROVISIONING_ADMIN_ID, resolveCaller } from '../auth'
import type { Env } from '../env'
import { hashToken } from '../secret'
import { createHarness, seedUser } from './helpers/harness'

// SEC-1: the local-dev bypass guard in `resolveCaller`. The bypass resolves an unauthenticated
// global-admin caller so the example app / admin scripts work against `lopata`/`wrangler dev`. It
// must be IMPOSSIBLE outside local dev — so it fires ONLY when ENVIRONMENT=local AND no durable
// signing keys are configured AND no credential is presented. Plus the `px_` key resolution path.

const REQUEST = 'r1'

/** env slice resolveCaller needs. Default: no durable signing keys (the dev signal), no provisioning key. */
function env(signingKeys = '', provisioningKey = ''): Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'PROPUSTKA_PROVISIONING_KEY' | 'ENVIRONMENT'> {
	return { PROPUSTKA_SIGNING_KEYS: signingKeys, PROPUSTKA_PROVISIONING_KEY: provisioningKey, ENVIRONMENT: 'local' }
}

describe('resolveCaller — local dev bypass (SEC-1 guard)', () => {
	test('fires in local with no signing keys and no credential → global-admin caller', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'local' })
		const res = await resolveCaller(services, env(), { app: 'reports', credential: null, requestId: REQUEST })
		expect(res.ok).toBe(true)
		if (!res.ok) throw new Error('unreachable')
		expect(res.caller.id).toBe(LOCAL_DEV_ADMIN_ID)
		expect(res.caller.permissions).toEqual([{ action: '*', scope: null, source: 'bootstrap' }])
		// Unlike the old CF-Access bypass, the verified app IS the requested app.
		expect(res.verifiedApp).toBe('reports')
	})

	test('does NOT fire in stage (no credential → missing_token)', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage' })
		const res = await resolveCaller(services, env(), { app: 'reports', credential: null, requestId: REQUEST })
		expect(res).toEqual({ ok: false, reason: 'missing_token' })
	})

	test('does NOT fire in local when durable signing keys ARE configured', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'local' })
		const res = await resolveCaller(services, env('[{"kty":"EC"}]'), { app: 'reports', credential: null, requestId: REQUEST })
		expect(res).toEqual({ ok: false, reason: 'missing_token' })
	})
})

describe('resolveCaller — px_ key resolution', () => {
	test('an unknown px_ key → invalid_token', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage' })
		const res = await resolveCaller(services, env(), { app: 'reports', credential: 'px_nope', requestId: REQUEST })
		expect(res).toEqual({ ok: false, reason: 'invalid_token' })
	})

	test('a valid anonymous px_ key resolves to an anonymous caller carrying its frozen grants', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage' })
		const issuerId = seedUser(h.sqlite, { sub: 'iss', email: 'iss@contember.com' })
		const key = 'px_share-link'
		const credId = await h.db.createCredential({
			tokenHash: await hashToken(key),
			issuedBy: issuerId,
			grants: [{ action: 'report.read' }],
		})

		const res = await resolveCaller(services, env(), { app: 'reports', credential: key, requestId: REQUEST })
		expect(res.ok).toBe(true)
		if (!res.ok) throw new Error('unreachable')
		// Anonymous (no principal binding) → no `type`; subject is the credential id.
		expect(res.caller.type).toBeUndefined()
		expect(res.caller.id).toBe(credId)
		expect(res.caller.permissions).toEqual([{ action: 'report.read', scope: null, source: 'grant' }])
	})
})

// The SEEDED PROVISIONING KEY: a single operator-generated `px_` held only in env (PROPUSTKA_PROVISIONING_KEY),
// never in the DB. Recognized at resolution time BEFORE the DB lookup — the machine analog of
// IAM_BOOTSTRAP_ADMINS, so a fresh control plane can reconcile/issue before any admin credential exists.
describe('resolveCaller — seeded provisioning key', () => {
	const PROVISIONING_KEY = 'px_provisioning-secret'

	test('a bearer matching PROPUSTKA_PROVISIONING_KEY → synthetic global-admin, no DB row', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage' })
		const res = await resolveCaller(services, env('', PROVISIONING_KEY), { app: 'vozka', credential: PROVISIONING_KEY, requestId: REQUEST })
		expect(res.ok).toBe(true)
		if (!res.ok) throw new Error('unreachable')
		expect(res.caller.id).toBe(PROVISIONING_ADMIN_ID)
		expect(res.caller.type).toBe('service')
		expect(res.caller.label).toBe('provisioning')
		expect(res.caller.permissions).toEqual([{ action: '*', scope: null, source: 'bootstrap' }])
		expect(res.verifiedApp).toBe('vozka')
	})

	test('a different px_ key does NOT match → falls through to the DB path (invalid_token)', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage' })
		const res = await resolveCaller(services, env('', PROVISIONING_KEY), {
			app: 'vozka',
			credential: 'px_not-the-provisioning-key',
			requestId: REQUEST,
		})
		expect(res).toEqual({ ok: false, reason: 'invalid_token' })
	})

	test('empty PROPUSTKA_PROVISIONING_KEY disables the seed (the same token resolves via the DB → invalid)', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage' })
		const res = await resolveCaller(services, env('', ''), { app: 'vozka', credential: PROVISIONING_KEY, requestId: REQUEST })
		expect(res).toEqual({ ok: false, reason: 'invalid_token' })
	})
})
