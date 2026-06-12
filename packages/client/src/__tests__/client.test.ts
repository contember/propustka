import type { ResolvedPrincipal } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { IamClient } from '../client'
import type { AuthContext, AuthFailure, Capability, CapabilityFailure, IssuedCapability, IssueFailure } from '../types'
import { IamRpcStub, makeRequest } from './stub'

const principal = (overrides: Partial<ResolvedPrincipal> = {}): ResolvedPrincipal => ({
	id: 'pr-1',
	type: 'user',
	label: 'alice@example.com',
	permissions: [],
	requestId: 'req-1',
	...overrides,
})

// Per-surface narrowing helpers: assert ok and return the rich surface, failing loudly
// otherwise. Concrete (non-generic) unions narrow correctly via the guard — no cast.
function expectAuth(result: AuthContext | AuthFailure): AuthContext {
	expect(result.ok).toBe(true)
	if (!result.ok) {
		throw new Error('expected an AuthContext')
	}
	return result
}

function expectCap(result: Capability | CapabilityFailure): Capability {
	expect(result.ok).toBe(true)
	if (!result.ok) {
		throw new Error('expected a Capability')
	}
	return result
}

function expectIssued(result: IssuedCapability | IssueFailure): IssuedCapability {
	expect(result.ok).toBe(true)
	if (!result.ok) {
		throw new Error('expected an IssuedCapability')
	}
	return result
}

describe('IamClient.authenticate', () => {
	test('ok → AuthContext', async () => {
		const stub = new IamRpcStub({ authenticate: { ok: true, principal: principal() } })
		const iam = new IamClient(stub, 'app-x')
		const auth = await iam.authenticate(makeRequest({ token: 'jwt', cookie: 'cookie', ray: 'ray-9' }))
		expect(auth.ok).toBe(true)
	})

	test('forwards app + parsed credentials + origin + cf-ray to the binding', async () => {
		const stub = new IamRpcStub({ authenticate: { ok: true, principal: principal() } })
		const iam = new IamClient(stub, 'app-x')
		await iam.authenticate(makeRequest({ url: 'https://foo.example.com/p', token: 'jwt', cookie: 'ck', ray: 'ray-1' }))
		expect(stub.authenticateInputs[0]).toEqual({
			app: 'app-x',
			token: 'jwt',
			cookie: 'ck',
			origin: 'https://foo.example.com',
			requestId: 'ray-1',
		})
	})

	test('absent token/cookie → null; missing cf-ray → generated requestId', async () => {
		const stub = new IamRpcStub({ authenticate: { ok: true, principal: principal() } })
		const iam = new IamClient(stub, 'app-x')
		await iam.authenticate(makeRequest())
		const input = stub.authenticateInputs[0]
		expect(input?.token).toBeNull()
		expect(input?.cookie).toBeNull()
		expect(typeof input?.requestId).toBe('string')
		expect(input?.requestId.length).toBeGreaterThan(0)
	})

	test('failure → status mapping', async () => {
		const cases: { reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled'; status: 401 | 403 }[] = [
			{ reason: 'missing_token', status: 401 },
			{ reason: 'invalid_token', status: 401 },
			{ reason: 'unknown_principal', status: 403 },
			{ reason: 'disabled', status: 403 },
		]
		for (const c of cases) {
			const stub = new IamRpcStub({ authenticate: { ok: false, reason: c.reason } })
			const iam = new IamClient(stub, 'app-x')
			const auth = await iam.authenticate(makeRequest())
			expect(auth.ok).toBe(false)
			if (auth.ok) {
				throw new Error('unreachable')
			}
			expect(auth.reason).toBe(c.reason)
			expect(auth.status).toBe(c.status)
		}
	})
})

describe('AuthContext.can', () => {
	const ctx = async (perms: ResolvedPrincipal['permissions']): Promise<AuthContext> => {
		const stub = new IamRpcStub({ authenticate: { ok: true, principal: principal({ permissions: perms }) } })
		const result = await new IamClient(stub, 'app-x').authenticate(makeRequest())
		return expectAuth(result)
	}

	test('scope-less check satisfied by a global entry only', async () => {
		const global = await ctx([{ action: 'project.read', scope: null, source: 'grant' }])
		expect(global.can('project.read')).toBe(true)

		const scoped = await ctx([{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(scoped.can('project.read')).toBe(false)
	})

	test('scoped check satisfied by same-scope or global entry', async () => {
		const scoped = await ctx([{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(scoped.can('project.read', { type: 'project', value: 'p1' })).toBe(true)
		expect(scoped.can('project.read', { type: 'project', value: 'p2' })).toBe(false)
		// A different dimension never satisfies, even with a matching value.
		expect(scoped.can('project.read', { type: 'organization', value: 'p1' })).toBe(false)

		const global = await ctx([{ action: 'project.*', scope: null, source: 'grant' }])
		expect(global.can('project.read', { type: 'project', value: 'p2' })).toBe(true)
	})
})

describe('AuthContext.scopedTo', () => {
	const ctx = async (perms: ResolvedPrincipal['permissions']): Promise<AuthContext> => {
		const stub = new IamRpcStub({ authenticate: { ok: true, principal: principal({ permissions: perms }) } })
		const result = await new IamClient(stub, 'app-x').authenticate(makeRequest())
		return expectAuth(result)
	}

	test('null when ANY matching entry is global (unrestricted)', async () => {
		const auth = await ctx([
			{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' },
			{ action: 'project.*', scope: null, source: 'bootstrap' },
		])
		expect(auth.scopedTo('project.read', 'project')).toBeNull()
	})

	test('empty array when the action matches no entry', async () => {
		const auth = await ctx([{ action: 'report.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(auth.scopedTo('project.read', 'project')).toEqual([])
	})

	test('distinct scope values within the dimension', async () => {
		const auth = await ctx([
			{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' },
			{ action: 'project.read', scope: { type: 'project', value: 'p2' }, source: 'grant' },
			{ action: 'project.*', scope: { type: 'project', value: 'p1' }, source: 'group:org/team' }, // dup p1 via wildcard
		])
		expect(auth.scopedTo('project.read', 'project')).toEqual(['p1', 'p2'])
	})

	test('entries in other dimensions are ignored', async () => {
		const auth = await ctx([
			{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' },
			{ action: 'project.read', scope: { type: 'organization', value: 'acme' }, source: 'grant' },
		])
		// Asking for the 'project' dimension never sees the 'organization' grant.
		expect(auth.scopedTo('project.read', 'project')).toEqual(['p1'])
		expect(auth.scopedTo('project.read', 'organization')).toEqual(['acme'])
	})
})

describe('AuthContext.audit', () => {
	test('injects app/principal/requestId and forwards domain fields', async () => {
		const stub = new IamRpcStub({
			authenticate: { ok: true, principal: principal({ id: 'pr-9', label: 'bob@x', requestId: 'req-42' }) },
		})
		const auth = expectAuth(await new IamClient(stub, 'app-y').authenticate(makeRequest()))
		await auth.audit({ action: 'project.update', resourceType: 'project', resourceId: 'p1', diff: { a: [1, 2] } })
		expect(stub.auditCalls[0]).toEqual({
			app: 'app-y',
			requestId: 'req-42',
			principalId: 'pr-9',
			principalLabel: 'bob@x',
			action: 'project.update',
			resourceType: 'project',
			resourceId: 'p1',
			diff: { a: [1, 2] },
			metadata: undefined,
		})
	})
})

describe('IamClient.redeemCapability', () => {
	const cap = async (caps: { action: string; resource: string }[], label: string | null = null): Promise<Capability> => {
		const stub = new IamRpcStub({ redeem: { ok: true, capabilities: caps, tokenId: 'tok-1', label } })
		const result = await new IamClient(stub, 'app-x').redeemCapability(makeRequest({ ray: 'ray-7' }), 'the-token')
		return expectCap(result)
	}

	test('can() is exact (action, resource) match — no wildcards', async () => {
		const c = await cap([{ action: 'report.read', resource: 'report:q2' }])
		expect(c.can('report.read', 'report:q2')).toBe(true)
		expect(c.can('report.read', 'report:q3')).toBe(false)
		expect(c.can('report.write', 'report:q2')).toBe(false)
		// Wildcards must NOT widen a capability.
		expect(c.can('report.*', 'report:q2')).toBe(false)
	})

	test('forwards app + token + requestId to the binding', async () => {
		const stub = new IamRpcStub({ redeem: { ok: true, capabilities: [], tokenId: 't', label: null } })
		await new IamClient(stub, 'app-z').redeemCapability(makeRequest({ ray: 'ray-3' }), 'tok')
		expect(stub.redeemInputs[0]).toEqual({ app: 'app-z', token: 'tok', requestId: 'ray-3' })
	})

	test('failure → 404 regardless of reason', async () => {
		for (const reason of ['unknown', 'expired', 'revoked', 'exhausted'] as const) {
			const stub = new IamRpcStub({ redeem: { ok: false, reason } })
			const result = await new IamClient(stub, 'app-x').redeemCapability(makeRequest(), 'tok')
			expect(result.ok).toBe(false)
			if (result.ok) {
				throw new Error('unreachable')
			}
			expect(result.reason).toBe(reason)
			expect(result.status).toBe(404)
		}
	})

	test('audit injects capabilityTokenId + label, principalId null', async () => {
		const stub = new IamRpcStub({ redeem: { ok: true, capabilities: [], tokenId: 'tok-X', label: 'Share Q2' } })
		const c = expectCap(await new IamClient(stub, 'app-x').redeemCapability(makeRequest({ ray: 'ray-5' }), 'tok'))
		await c.audit({ action: 'report.feedback.create', resourceType: 'report', resourceId: 'q2' })
		expect(stub.auditCalls[0]).toEqual({
			app: 'app-x',
			requestId: 'ray-5',
			principalId: null,
			principalLabel: 'Share Q2',
			capabilityTokenId: 'tok-X',
			action: 'report.feedback.create',
			resourceType: 'report',
			resourceId: 'q2',
			diff: undefined,
			metadata: undefined,
		})
	})

	test('audit label falls back to capability:<id> when unlabeled', async () => {
		const stub = new IamRpcStub({ redeem: { ok: true, capabilities: [], tokenId: 'tok-Y', label: null } })
		const c = expectCap(await new IamClient(stub, 'app-x').redeemCapability(makeRequest(), 'tok'))
		await c.audit({ action: 'report.read', resourceType: 'report' })
		expect(stub.auditCalls[0]?.principalLabel).toBe('capability:tok-Y')
	})
})

describe('IamClient.issueCapability', () => {
	test('ok → IssuedCapability and forwards issuer credentials + grants', async () => {
		const stub = new IamRpcStub({ issue: { ok: true, token: 'plaintext', id: 'cap-1' } })
		const iam = new IamClient(stub, 'app-x')
		const result = await iam.issueCapability(
			makeRequest({ url: 'https://r.example.com/x', token: 'jwt', cookie: 'ck', ray: 'ray-2' }),
			{
				grants: [{ action: 'report.read', resource: 'report:q2', scope: { type: 'project', value: 'p1' } }],
				label: 'Share',
				expiresAt: 99,
				maxUses: 3,
			},
		)
		const ok = expectIssued(result)
		expect(ok.token).toBe('plaintext')
		expect(ok.id).toBe('cap-1')
		expect(stub.issueInputs[0]).toEqual({
			app: 'app-x',
			token: 'jwt',
			cookie: 'ck',
			origin: 'https://r.example.com',
			requestId: 'ray-2',
			grants: [{ action: 'report.read', resource: 'report:q2', scope: { type: 'project', value: 'p1' } }],
			label: 'Share',
			expiresAt: 99,
			maxUses: 3,
		})
	})

	test('failure → status mapping', async () => {
		const cases: {
			reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed'
			status: 401 | 403
		}[] = [
			{ reason: 'missing_token', status: 401 },
			{ reason: 'invalid_token', status: 401 },
			{ reason: 'unknown_principal', status: 403 },
			{ reason: 'disabled', status: 403 },
			{ reason: 'not_allowed', status: 403 },
		]
		for (const c of cases) {
			const stub = new IamRpcStub({ issue: { ok: false, reason: c.reason } })
			const result = await new IamClient(stub, 'app-x').issueCapability(makeRequest(), { grants: [] })
			expect(result.ok).toBe(false)
			if (result.ok) {
				throw new Error('unreachable')
			}
			expect(result.reason).toBe(c.reason)
			expect(result.status).toBe(c.status)
		}
	})
})

describe('IamClient.revokeCapability', () => {
	test('ok → forwards caller credentials + tokenId, returns revoked flag', async () => {
		const stub = new IamRpcStub({ revoke: { ok: true, revoked: true } })
		const iam = new IamClient(stub, 'app-x')
		const result = await iam.revokeCapability(
			makeRequest({ url: 'https://r.example.com/x', token: 'jwt', cookie: 'ck', ray: 'ray-9' }),
			'cap-7',
		)
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('unreachable')
		}
		expect(result.revoked).toBe(true)
		expect(stub.revokeInputs[0]).toEqual({
			app: 'app-x',
			token: 'jwt',
			cookie: 'ck',
			origin: 'https://r.example.com',
			requestId: 'ray-9',
			tokenId: 'cap-7',
		})
	})

	test('already revoked → ok with revoked:false (idempotent)', async () => {
		const stub = new IamRpcStub({ revoke: { ok: true, revoked: false } })
		const result = await new IamClient(stub, 'app-x').revokeCapability(makeRequest(), 'cap-7')
		expect(result).toEqual({ ok: true, revoked: false })
	})

	test('failure → status mapping (not_found → 404)', async () => {
		const cases: {
			reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' | 'not_allowed' | 'not_found'
			status: 401 | 403 | 404
		}[] = [
			{ reason: 'missing_token', status: 401 },
			{ reason: 'invalid_token', status: 401 },
			{ reason: 'unknown_principal', status: 403 },
			{ reason: 'disabled', status: 403 },
			{ reason: 'not_allowed', status: 403 },
			{ reason: 'not_found', status: 404 },
		]
		for (const c of cases) {
			const stub = new IamRpcStub({ revoke: { ok: false, reason: c.reason } })
			const result = await new IamClient(stub, 'app-x').revokeCapability(makeRequest(), 'cap-7')
			expect(result.ok).toBe(false)
			if (result.ok) {
				throw new Error('unreachable')
			}
			expect(result.reason).toBe(c.reason)
			expect(result.status).toBe(c.status)
		}
	})
})
