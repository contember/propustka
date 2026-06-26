import { describe, expect, test } from 'bun:test'
import { hashToken } from '../secret'
import { createHarness, seedUser } from './helpers/harness'

const FUTURE = Math.floor(Date.now() / 1000) + 3600
const PAST = Math.floor(Date.now() / 1000) - 3600

describe('sessions db', () => {
	test('create → look up an active session by the cookie hash', async () => {
		const h = createHarness()
		const principal = seedUser(h.sqlite, { sub: 'g-1', email: 'a@b.cz' })
		const hash = await hashToken('session-cookie-value')

		const id = await h.db.createSession({ tokenHash: hash, principalId: principal, idpSub: 'g-1', email: 'a@b.cz', expiresAt: FUTURE })
		expect(id).toBeTruthy()

		const row = await h.db.getActiveSessionByHash(hash)
		expect(row?.principal_id).toBe(principal)
		expect(row?.idp_sub).toBe('g-1')
		expect(row?.email).toBe('a@b.cz')
	})

	test('an expired session does not resolve', async () => {
		const h = createHarness()
		const principal = seedUser(h.sqlite, { sub: 'g-2', email: 'c@d.cz' })
		const hash = await hashToken('expired')
		await h.db.createSession({ tokenHash: hash, principalId: principal, idpSub: 'g-2', expiresAt: PAST })
		expect(await h.db.getActiveSessionByHash(hash)).toBeNull()
	})

	test('revoke makes the session stop resolving (idempotent)', async () => {
		const h = createHarness()
		const principal = seedUser(h.sqlite, { sub: 'g-3', email: 'e@f.cz' })
		const hash = await hashToken('to-revoke')
		await h.db.createSession({ tokenHash: hash, principalId: principal, idpSub: 'g-3', expiresAt: FUTURE })

		expect(await h.db.revokeSessionByHash(hash)).toBe(true)
		expect(await h.db.getActiveSessionByHash(hash)).toBeNull()
		// Second revoke is a no-op.
		expect(await h.db.revokeSessionByHash(hash)).toBe(false)
	})

	test('an unknown hash resolves to null', async () => {
		const h = createHarness()
		expect(await h.db.getActiveSessionByHash(await hashToken('nope'))).toBeNull()
	})

	test('list sessions for a principal, newest first', async () => {
		const h = createHarness()
		const principal = seedUser(h.sqlite, { sub: 'g-4', email: 'g@h.cz' })
		await h.db.createSession({ tokenHash: await hashToken('s1'), principalId: principal, idpSub: 'g-4', expiresAt: FUTURE })
		await h.db.createSession({ tokenHash: await hashToken('s2'), principalId: principal, idpSub: 'g-4', expiresAt: FUTURE })
		expect((await h.db.listSessionsForPrincipal(principal)).length).toBe(2)
	})

	test('prune removes expired and revoked sessions', async () => {
		const h = createHarness()
		const principal = seedUser(h.sqlite, { sub: 'g-5', email: 'i@j.cz' })
		await h.db.createSession({ tokenHash: await hashToken('live'), principalId: principal, idpSub: 'g-5', expiresAt: FUTURE })
		await h.db.createSession({ tokenHash: await hashToken('dead'), principalId: principal, idpSub: 'g-5', expiresAt: PAST })
		const revokedHash = await hashToken('killed')
		await h.db.createSession({ tokenHash: revokedHash, principalId: principal, idpSub: 'g-5', expiresAt: FUTURE })
		await h.db.revokeSessionByHash(revokedHash)

		const removed = await h.db.pruneSessions(Math.floor(Date.now() / 1000))
		expect(removed).toBe(2)
		expect((await h.db.listSessionsForPrincipal(principal)).length).toBe(1)
	})
})
