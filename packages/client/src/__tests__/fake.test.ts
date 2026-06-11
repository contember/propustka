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
		expect(auth.can('project.update', { project: 'p1' })).toBe(true)
	})

	test('deny-list blocks matching actions (wildcards apply)', async () => {
		const auth = await new FakeIamClient({ deny: ['project.*', 'report.delete'] }).authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.can('project.update')).toBe(false)
		expect(auth.can('project.read', { project: 'p1' })).toBe(false)
		expect(auth.can('report.delete')).toBe(false)
		expect(auth.can('report.read')).toBe(true)
	})

	test('scopedTo → null (unrestricted)', async () => {
		const auth = await new FakeIamClient({ deny: ['project.*'] }).authenticate(makeRequest())
		if (!auth.ok) {
			throw new Error('unreachable')
		}
		expect(auth.scopedTo('project.read')).toBeNull()
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
		'admin@x.test': { id: 'p-admin', label: 'admin@x.test', permissions: [{ action: '*', projectId: null, source: 'grant' as const }] },
		'appwide@x.test': { id: 'p-appwide', label: 'appwide@x.test', permissions: [{ action: 'project.read', projectId: null, source: 'grant' as const }] },
		'scoped@x.test': { id: 'p-scoped', label: 'scoped@x.test', permissions: [{ action: 'project.read', projectId: 'proj-web', source: 'grant' as const }] },
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
		expect(auth.can('project.read', { project: 'anything' })).toBe(true)
		expect(auth.scopedTo('project.read')).toBeNull()
	})

	test('app-wide persona: global project.read, no admin surface', async () => {
		const auth = await client.authenticate(reqWithCookie('appwide@x.test'))
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.can('member.manage')).toBe(false)
		expect(auth.can('project.read', { project: 'proj-web' })).toBe(true)
		expect(auth.scopedTo('project.read')).toBeNull()
	})

	test('project-scoped persona: only its project', async () => {
		const auth = await client.authenticate(reqWithCookie('scoped@x.test'))
		if (!auth.ok) throw new Error('unreachable')
		expect(auth.can('project.read', { project: 'proj-web' })).toBe(true)
		expect(auth.can('project.read', { project: 'proj-api' })).toBe(false)
		expect(auth.can('member.manage')).toBe(false)
		expect(auth.scopedTo('project.read')).toEqual(['proj-web'])
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
