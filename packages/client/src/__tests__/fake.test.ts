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
