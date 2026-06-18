import { describe, expect, test } from 'bun:test'
import { resolveRequest } from '../auth'
import { createHarness, seedInlineGrant, seedService, seedUser } from './helpers/harness'

// listPrincipals (the app's people directory): the DB layer's app-scoped, user-only,
// deduped enumeration (`getPrincipalsForApp`) plus the aud-derived isolation through the
// real resolve path — an operator only ever sees the roster of the app it authenticates to.

describe('Db.getPrincipalsForApp', () => {
	test('returns app + cross-app users, excludes other apps and services, dedups, flags disabled', () => {
		const h = createHarness()

		const inPoplach = seedUser(h.sqlite, { sub: 'a', email: 'a@poplach.test' })
		seedInlineGrant(h.sqlite, inPoplach, ['project.read'], null, 'poplach')

		const crossApp = seedUser(h.sqlite, { sub: 'b', email: 'b@poplach.test' })
		seedInlineGrant(h.sqlite, crossApp, ['*'], null, null) // app NULL = all apps

		const inOpice = seedUser(h.sqlite, { sub: 'c', email: 'c@opice.test' })
		seedInlineGrant(h.sqlite, inOpice, ['project.read'], null, 'opice')

		const disabled = seedUser(h.sqlite, { sub: 'd', email: 'd@poplach.test', disabled: true })
		seedInlineGrant(h.sqlite, disabled, ['project.read'], null, 'poplach')

		const multiGrant = seedUser(h.sqlite, { sub: 'e', email: 'e@poplach.test' })
		seedInlineGrant(h.sqlite, multiGrant, ['project.read'], null, 'poplach')
		seedInlineGrant(h.sqlite, multiGrant, ['member.manage'], null, 'poplach')

		const service = seedService(h.sqlite, { commonName: 'ci-bot' })
		seedInlineGrant(h.sqlite, service, ['report.write'], null, 'poplach')

		return h.db.getPrincipalsForApp('poplach').then((rows) => {
			const ids = rows.map((r) => r.id)
			expect(new Set(ids)).toEqual(new Set([inPoplach, crossApp, disabled, multiGrant]))
			expect(ids).not.toContain(inOpice) // other app's user excluded
			expect(ids).not.toContain(service) // services are not people
			expect(ids.filter((id) => id === multiGrant)).toHaveLength(1) // deduped across grants
			expect(rows.find((r) => r.id === disabled)?.disabled_at).not.toBeNull()
		})
	})

	test('an app with only the cross-app user still returns it; an unknown app returns just cross-app', async () => {
		const h = createHarness()
		const crossApp = seedUser(h.sqlite, { sub: 'b', email: 'b@x.test' })
		seedInlineGrant(h.sqlite, crossApp, ['*'], null, null)
		const opiceOnly = seedUser(h.sqlite, { sub: 'c', email: 'c@opice.test' })
		seedInlineGrant(h.sqlite, opiceOnly, ['project.read'], null, 'opice')

		expect((await h.db.getPrincipalsForApp('whatever')).map((r) => r.id)).toEqual([crossApp])
	})

	test('expired grants do not make a user a member', async () => {
		const h = createHarness()
		const expired = seedUser(h.sqlite, { sub: 'x', email: 'x@poplach.test' })
		// expires_at in the past → not an active member.
		h.sqlite.run(
			'INSERT INTO grants (id, principal_id, permissions, app, expires_at) VALUES (?, ?, ?, ?, ?)',
			['g-exp', expired, JSON.stringify(['project.read']), 'poplach', 1],
		)
		expect(await h.db.getPrincipalsForApp('poplach')).toEqual([])
	})
})

describe('aud-derived isolation (resolve → roster)', () => {
	const ACCESS_APPS = { 'aud-poplach': 'poplach', 'aud-opice': 'opice' }

	test('an operator authenticated for poplach resolves to the poplach roster, never opice', async () => {
		const h = createHarness()
		const services = h.makeServices({ environment: 'stage', accessApps: ACCESS_APPS })

		const caller = seedUser(h.sqlite, { sub: 'op-sub', email: 'op@poplach.test' })
		seedInlineGrant(h.sqlite, caller, ['project.read'], null, 'poplach')
		const teammate = seedUser(h.sqlite, { sub: 't-sub', email: 'teammate@poplach.test' })
		seedInlineGrant(h.sqlite, teammate, ['project.read'], null, 'poplach')
		const opicePerson = seedUser(h.sqlite, { sub: 'o-sub', email: 'someone@opice.test' })
		seedInlineGrant(h.sqlite, opicePerson, ['project.read'], null, 'opice')

		const token = await h.signToken({ sub: 'op-sub', email: 'op@poplach.test' }, { audience: 'aud-poplach' })
		const outcome = await resolveRequest(services, { app: 'poplach', token, cookie: null, origin: null, requestId: 'r1' })
		expect(outcome.result.ok).toBe(true)
		expect(outcome.verifiedApp).toBe('poplach')

		const roster = await h.db.getPrincipalsForApp(outcome.verifiedApp!)
		const emails = roster.map((r) => r.email)
		expect(new Set(emails)).toEqual(new Set(['op@poplach.test', 'teammate@poplach.test']))
		expect(emails).not.toContain('someone@opice.test')
	})
})
