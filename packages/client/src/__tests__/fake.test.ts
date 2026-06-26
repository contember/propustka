import { describe, expect, test } from 'bun:test'
import { FakeIamClient } from '../fake'
import { makeRequest } from './stub'

describe('FakeIamClient.listPrincipals', () => {
	const personas = {
		'admin@x.test': { id: 'p-admin', label: 'admin@x.test', permissions: [{ action: '*', scope: null, source: 'grant' as const }] },
		'appwide@x.test': {
			id: 'p-appwide',
			label: 'appwide@x.test',
			permissions: [{ action: 'project.read', scope: null, source: 'grant' as const }],
		},
		'scoped@x.test': {
			id: 'p-scoped',
			label: 'scoped@x.test',
			permissions: [{ action: 'project.read', scope: { type: 'project', value: 'proj-web' }, source: 'grant' as const }],
		},
	}

	test('enumerates the configured personas as the dev roster', async () => {
		const result = await new FakeIamClient({ personas }).listPrincipals(new Request('https://app.example.com/'))
		if (!result.ok) throw new Error('unreachable')
		const byId = new Map(result.principals.map((p) => [p.id, p]))
		expect(new Set(byId.keys())).toEqual(new Set(['p-admin', 'p-appwide', 'p-scoped']))
		// A user's label is their email; nobody is disabled in the fixture.
		expect(byId.get('p-appwide')).toEqual({ id: 'p-appwide', type: 'user', label: 'appwide@x.test', email: 'appwide@x.test', disabled: false })
	})

	test('falls back to the single fixed identity when no personas are configured', async () => {
		const result = await new FakeIamClient({ principal: { id: 'solo', label: 'solo@x.test' } }).listPrincipals(
			new Request('https://app.example.com/'),
		)
		if (!result.ok) throw new Error('unreachable')
		expect(result.principals).toEqual([{ id: 'solo', type: 'user', label: 'solo@x.test', email: 'solo@x.test', disabled: false }])
	})
})

describe('FakeIamClient.issueKey', () => {
	test('always ok with a fake px_ token + id', async () => {
		const issued = await new FakeIamClient().issueKey(makeRequest(), { permissions: [] })
		expect(issued.ok).toBe(true)
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		expect(issued.token.startsWith('px_fake-')).toBe(true)
		expect(issued.id.startsWith('fake-cred-')).toBe(true)
		// A standalone (anonymous) share link is bound to no principal.
		expect(issued.principalId).toBeUndefined()
	})

	test('service mode → binds the key to a fresh fake service principal', async () => {
		const issued = await new FakeIamClient().issueKey(makeRequest(), {
			service: { label: 'ci-bot', permissions: ['report.write'], scope: { type: 'project', value: 'p1' } },
		})
		expect(issued.ok).toBe(true)
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		expect(issued.token.startsWith('px_fake-')).toBe(true)
		expect(issued.principalId?.startsWith('fake-service-')).toBe(true)
	})
})

describe('FakeIamClient.issueJwt', () => {
	test('always ok with a fake passthrough token + expiry', async () => {
		const issued = await new FakeIamClient().issueJwt(makeRequest(), { permissions: [{ action: 'report.read', scope: null }] })
		expect(issued.ok).toBe(true)
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		expect(issued.token.startsWith('fake-jwt-')).toBe(true)
		expect(typeof issued.expiresAt).toBe('number')
	})
})

describe('FakeIamClient.revokeKey', () => {
	test('issue → revoke flips the credential (in-memory registry stays consistent)', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueKey(makeRequest(), { permissions: [] })
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		expect(await fake.revokeKey(makeRequest(), issued.id)).toEqual({ ok: true, revoked: true })
	})

	test('second revoke is idempotent (revoked:false)', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueKey(makeRequest(), { permissions: [] })
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		await fake.revokeKey(makeRequest(), issued.id)
		expect(await fake.revokeKey(makeRequest(), issued.id)).toEqual({ ok: true, revoked: false })
	})

	test('unknown id → not_found (404)', async () => {
		const revoked = await new FakeIamClient().revokeKey(makeRequest(), 'never-issued')
		expect(revoked.ok).toBe(false)
		if (revoked.ok) {
			throw new Error('unreachable')
		}
		expect(revoked.reason).toBe('not_found')
		expect(revoked.status).toBe(404)
	})
})
