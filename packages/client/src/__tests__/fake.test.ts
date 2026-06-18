import { describe, expect, test } from 'bun:test'
import { FakeIamClient } from '../fake'
import { makeRequest } from './stub'

describe('FakeIamClient.authenticate', () => {
	test('allow-all by default', async () => {
		const auth = await new FakeIamClient().authenticate(makeRequest())
		expect(auth.ok).toBe(true)
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.can('anything.at.all')).toBe(true)
		expect(auth.can('project.update', { type: 'project', value: 'p1' })).toBe(true)
	})

	test('deny-list blocks matching actions (wildcards apply)', async () => {
		const auth = await new FakeIamClient({ deny: ['project.*', 'report.delete'] }).authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.can('project.update')).toBe(false)
		expect(auth.can('project.read', { type: 'project', value: 'p1' })).toBe(false)
		expect(auth.can('report.delete')).toBe(false)
		expect(auth.can('report.read')).toBe(true)
	})

	test('scopedTo → null (unrestricted)', async () => {
		const auth = await new FakeIamClient({ deny: ['project.*'] }).authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.scopedTo('project.read', 'project')).toBeNull()
	})

	test('audit is a resolved no-op', async () => {
		const auth = await new FakeIamClient().authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		await expect(auth.audit({ action: 'x.y', resourceType: 'x' })).resolves.toBeUndefined()
	})

	test('principal exposes the fixed fake identity (default)', async () => {
		const auth = await new FakeIamClient().authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.principal).toEqual({ id: 'fake-principal', type: 'user', label: 'fake@example.com' })
	})

	test('principal reflects the configured override', async () => {
		const auth = await new FakeIamClient({
			principal: { id: 'mem-scoped', label: 'scoped@poplach.test', type: 'user' },
		}).authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.principal).toEqual({ id: 'mem-scoped', type: 'user', label: 'scoped@poplach.test' })
	})
})

describe('FakeIamClient persona mode', () => {
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
	const client = new FakeIamClient({ personas, defaultPersona: 'appwide@x.test' })

	function reqWithCookie(value: string): Request {
		return new Request('https://app.example.com/', { headers: { Cookie: `propustka_dev_principal=${value}` } })
	}

	test('cookie selects the admin persona (global, can manage)', async () => {
		const auth = await client.authenticate(reqWithCookie('admin@x.test'))
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.principal.id).toBe('p-admin')
		expect(auth.can('member.manage')).toBe(true)
		expect(auth.can('project.read', { type: 'project', value: 'anything' })).toBe(true)
		expect(auth.scopedTo('project.read', 'project')).toBeNull()
	})

	test('app-wide persona: global project.read, no admin surface', async () => {
		const auth = await client.authenticate(reqWithCookie('appwide@x.test'))
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.can('member.manage')).toBe(false)
		expect(auth.can('project.read', { type: 'project', value: 'proj-web' })).toBe(true)
		expect(auth.scopedTo('project.read', 'project')).toBeNull()
	})

	test('project-scoped persona: only its project', async () => {
		const auth = await client.authenticate(reqWithCookie('scoped@x.test'))
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.can('project.read', { type: 'project', value: 'proj-web' })).toBe(true)
		expect(auth.can('project.read', { type: 'project', value: 'proj-api' })).toBe(false)
		expect(auth.can('member.manage')).toBe(false)
		expect(auth.scopedTo('project.read', 'project')).toEqual(['proj-web'])
	})

	test('header selects the persona too (no cookie)', async () => {
		const req = new Request('https://app.example.com/', { headers: { 'X-Dev-Principal': 'scoped@x.test' } })
		const auth = await client.authenticate(req)
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.principal.id).toBe('p-scoped')
	})

	test('no selector → default persona', async () => {
		const auth = await client.authenticate(new Request('https://app.example.com/'))
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.principal.id).toBe('p-appwide')
	})

	test('unknown persona → unknown_principal (403)', async () => {
		const auth = await client.authenticate(reqWithCookie('ghost@x.test'))
		expect(auth.ok).toBe(false)
		if (auth.ok) throw new Error('unreachable')
		expect(auth.reason).toBe('unknown_principal')
		expect(auth.status).toBe(403)
	})

	test('no selector and no default → unknown_principal', async () => {
		const noDefault = new FakeIamClient({ personas })
		const auth = await noDefault.authenticate(new Request('https://app.example.com/'))
		expect(auth.ok).toBe(false)
	})

	test('resolve callback drives the persona dynamically (takes precedence)', async () => {
		const dynamic = new FakeIamClient({
			resolve: (req) => {
				const id = req.headers.get('X-Who')
				if (!id) return null
				return {
					id,
					label: `${id}@x.test`,
					permissions: [{ action: 'project.read', scope: { type: 'project', value: id }, source: 'grant' as const }],
				}
			},
		})
		const ok = await dynamic.authenticate(new Request('https://app.example.com/', { headers: { 'X-Who': 'proj-42' } }))
		if (!ok.ok) throw new Error('unreachable')
		expect(ok.principal.id).toBe('proj-42')
		expect(ok.scopedTo('project.read', 'project')).toEqual(['proj-42'])
		expect(ok.can('project.read', { type: 'project', value: 'proj-42' })).toBe(true)
		expect(ok.can('project.read', { type: 'project', value: 'other' })).toBe(false)

		const denied = await dynamic.authenticate(new Request('https://app.example.com/'))
		expect(denied.ok).toBe(false)
	})

	test('listPrincipals enumerates the configured personas as the dev roster', async () => {
		const result = await client.listPrincipals(new Request('https://app.example.com/'))
		if (!result.ok) throw new Error('unreachable')
		const byId = new Map(result.principals.map((p) => [p.id, p]))
		expect(new Set(byId.keys())).toEqual(new Set(['p-admin', 'p-appwide', 'p-scoped']))
		// A user's label is their email; nobody is disabled in the fixture.
		expect(byId.get('p-appwide')).toEqual({ id: 'p-appwide', type: 'user', label: 'appwide@x.test', email: 'appwide@x.test', disabled: false })
	})
})

describe('FakeIamClient.listPrincipals (simple mode)', () => {
	test('falls back to the single fixed identity when no personas are configured', async () => {
		const result = await new FakeIamClient({ principal: { id: 'solo', label: 'solo@x.test' } }).listPrincipals(
			new Request('https://app.example.com/'),
		)
		if (!result.ok) throw new Error('unreachable')
		expect(result.principals).toEqual([{ id: 'solo', type: 'user', label: 'solo@x.test', email: 'solo@x.test', disabled: false }])
	})
})

describe('FakeIamClient.redeemCapability', () => {
	test('returns a fake capability whose can() respects the deny list', async () => {
		const cap = await new FakeIamClient({ deny: ['report.delete'] }).redeemCapability(makeRequest(), 'tok')
		expect(cap.ok).toBe(true)
		if (!cap.ok) {
			throw new Error('unreachable')
		}
		expect(cap.can('report.read', 'report:q2')).toBe(true)
		expect(cap.can('report.delete', 'report:q2')).toBe(false)
		await expect(cap.audit({ action: 'report.read', resourceType: 'report' })).resolves.toBeUndefined()
	})
})

describe('FakeIamClient.issueCapability', () => {
	test('always ok with fake token + id', async () => {
		const issued = await new FakeIamClient().issueCapability(makeRequest(), { grants: [] })
		expect(issued.ok).toBe(true)
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		expect(issued.token.startsWith('fake-token-')).toBe(true)
		expect(issued.id.startsWith('fake-')).toBe(true)
	})
})

describe('FakeIamClient.revokeCapability', () => {
	test('issue → revoke → redeem reads revoked (in-memory registry stays consistent)', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueCapability(makeRequest(), { grants: [] })
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		// Before revoke, the issued token redeems fine.
		const before = await fake.redeemCapability(makeRequest(), issued.token)
		expect(before.ok).toBe(true)

		const revoked = await fake.revokeCapability(makeRequest(), issued.id)
		expect(revoked).toEqual({ ok: true, revoked: true })

		// After revoke, the SAME token reads 'revoked' (404), like the real Worker.
		const after = await fake.redeemCapability(makeRequest(), issued.token)
		expect(after.ok).toBe(false)
		if (after.ok) {
			throw new Error('unreachable')
		}
		expect(after.reason).toBe('revoked')
		expect(after.status).toBe(404)
	})

	test('second revoke is idempotent (revoked:false)', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueCapability(makeRequest(), { grants: [] })
		if (!issued.ok) {
			throw new Error('unreachable')
		}
		await fake.revokeCapability(makeRequest(), issued.id)
		expect(await fake.revokeCapability(makeRequest(), issued.id)).toEqual({ ok: true, revoked: false })
	})

	test('unknown id → not_found (404)', async () => {
		const revoked = await new FakeIamClient().revokeCapability(makeRequest(), 'never-issued')
		expect(revoked.ok).toBe(false)
		if (revoked.ok) {
			throw new Error('unreachable')
		}
		expect(revoked.reason).toBe('not_found')
		expect(revoked.status).toBe(404)
	})
})
