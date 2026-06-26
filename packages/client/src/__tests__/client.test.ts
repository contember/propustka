import type { AccessTokenClaims, PermissionEntry } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { buildAuthContext, IamClient } from '../client'
import type { AuthContext, IssuedKey, IssueFailure } from '../types'
import { IamRpcStub, makeRequest } from './stub'

// Build a real (`permits`-backed) AuthContext straight from access-token claims — the same path the
// SDK's gate produces after verifying a `px_token`. `can`/`scopedTo`/`audit` behave identically
// whether the claims came from a cookie session, a `px_` key, or a passthrough JWT.
function ctxWith(
	perms: PermissionEntry[],
	opts: { binding?: IamRpcStub; appId?: string; sub?: string; label?: string | null; requestId?: string } = {},
): AuthContext {
	const appId = opts.appId ?? 'app-x'
	const claims: AccessTokenClaims = {
		iss: 'https://iam.example.com',
		aud: appId,
		sub: opts.sub ?? 'pr-1',
		iat: 0,
		exp: 9_999_999_999,
		perms,
		ptype: 'user',
		label: opts.label ?? 'alice@example.com',
	}
	return buildAuthContext(opts.binding ?? new IamRpcStub(), appId, claims, opts.requestId ?? 'req-1')
}

function expectIssuedKey(result: IssuedKey | IssueFailure): IssuedKey {
	expect(result.ok).toBe(true)
	if (!result.ok) {
		throw new Error('expected an IssuedKey')
	}
	return result
}

describe('AuthContext.can', () => {
	test('scope-less check satisfied by a global entry only', () => {
		const global = ctxWith([{ action: 'project.read', scope: null, source: 'grant' }])
		expect(global.can('project.read')).toBe(true)

		const scoped = ctxWith([{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(scoped.can('project.read')).toBe(false)
	})

	test('scoped check satisfied by same-scope or global entry', () => {
		const scoped = ctxWith([{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(scoped.can('project.read', { type: 'project', value: 'p1' })).toBe(true)
		expect(scoped.can('project.read', { type: 'project', value: 'p2' })).toBe(false)
		// A different dimension never satisfies, even with a matching value.
		expect(scoped.can('project.read', { type: 'organization', value: 'p1' })).toBe(false)

		const global = ctxWith([{ action: 'project.*', scope: null, source: 'grant' }])
		expect(global.can('project.read', { type: 'project', value: 'p2' })).toBe(true)
	})
})

describe('AuthContext.scopedTo', () => {
	test('null when ANY matching entry is global (unrestricted)', () => {
		const auth = ctxWith([
			{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' },
			{ action: 'project.*', scope: null, source: 'bootstrap' },
		])
		expect(auth.scopedTo('project.read', 'project')).toBeNull()
	})

	test('empty array when the action matches no entry', () => {
		const auth = ctxWith([{ action: 'report.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(auth.scopedTo('project.read', 'project')).toEqual([])
	})

	test('distinct scope values within the dimension', () => {
		const auth = ctxWith([
			{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' },
			{ action: 'project.read', scope: { type: 'project', value: 'p2' }, source: 'grant' },
			{ action: 'project.*', scope: { type: 'project', value: 'p1' }, source: 'group:org/team' }, // dup p1 via wildcard
		])
		expect(auth.scopedTo('project.read', 'project')).toEqual(['p1', 'p2'])
	})

	test('entries in other dimensions are ignored', () => {
		const auth = ctxWith([
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
		const stub = new IamRpcStub()
		const auth = ctxWith([], { binding: stub, appId: 'app-y', sub: 'pr-9', label: 'bob@x', requestId: 'req-42' })
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

describe('IamClient.listPrincipals', () => {
	test('forwards the caller credential and returns the roster on success', async () => {
		const principals = [{ id: 'p1', type: 'user' as const, label: 'a@x.test', email: 'a@x.test', disabled: false }]
		const stub = new IamRpcStub({ listPrincipals: { ok: true, principals } })
		const result = await new IamClient(stub, 'app-z').listPrincipals(makeRequest({ bearer: 'px_ci', ray: 'ray-9' }))
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('unreachable')
		}
		expect(result.principals).toEqual(principals)
		expect(stub.listPrincipalsInputs[0]).toEqual({ app: 'app-z', credential: 'px_ci', requestId: 'ray-9' })
	})

	test('px_token cookie is used when no bearer is present', async () => {
		const stub = new IamRpcStub({ listPrincipals: { ok: true, principals: [] } })
		await new IamClient(stub, 'app-z').listPrincipals(makeRequest({ cookie: 'tok-abc', ray: 'ray-1' }))
		expect(stub.listPrincipalsInputs[0]).toEqual({ app: 'app-z', credential: 'tok-abc', requestId: 'ray-1' })
	})

	test('absent credential → null; missing cf-ray → generated requestId', async () => {
		const stub = new IamRpcStub({ listPrincipals: { ok: true, principals: [] } })
		await new IamClient(stub, 'app-z').listPrincipals(makeRequest())
		const input = stub.listPrincipalsInputs[0]
		expect(input?.credential).toBeNull()
		expect(typeof input?.requestId).toBe('string')
		expect(input?.requestId.length).toBeGreaterThan(0)
	})

	test('failure → status mapping (not_allowed → 403, missing_token → 401)', async () => {
		const denied = await new IamClient(new IamRpcStub({ listPrincipals: { ok: false, reason: 'not_allowed' } }), 'app-x').listPrincipals(makeRequest())
		expect(denied).toEqual({ ok: false, reason: 'not_allowed', status: 403 })
		const unauthed = await new IamClient(new IamRpcStub({ listPrincipals: { ok: false, reason: 'missing_token' } }), 'app-x').listPrincipals(
			makeRequest(),
		)
		expect(unauthed).toEqual({ ok: false, reason: 'missing_token', status: 401 })
	})
})

describe('IamClient.issueKey', () => {
	test('ok → IssuedKey and forwards the issuer credential + binding + grants', async () => {
		const stub = new IamRpcStub({ issueKey: { ok: true, token: 'px_plaintext', id: 'cred-1' } })
		const iam = new IamClient(stub, 'app-x')
		const result = await iam.issueKey(makeRequest({ bearer: 'px_ci', ray: 'ray-2' }), {
			permissions: [{ action: 'report.read', scope: { type: 'project', value: 'p1' } }],
			label: 'Share',
			expiresAt: 99,
		})
		const ok = expectIssuedKey(result)
		expect(ok.token).toBe('px_plaintext')
		expect(ok.id).toBe('cred-1')
		expect(stub.issueKeyInputs[0]).toEqual({
			app: 'app-x',
			credential: 'px_ci',
			requestId: 'ray-2',
			principalId: undefined,
			permissions: [{ action: 'report.read', scope: { type: 'project', value: 'p1' } }],
			label: 'Share',
			expiresAt: 99,
		})
	})

	test('service mode → forwards the service spec and returns the new principalId', async () => {
		const stub = new IamRpcStub({ issueKey: { ok: true, token: 'px_svc', id: 'cred-2', principalId: 'svc-1' } })
		const result = await new IamClient(stub, 'app-x').issueKey(
			makeRequest({ bearer: 'px_ci', ray: 'ray-3' }),
			{ service: { label: 'ci-bot', permissions: ['report.write'], scope: { type: 'project', value: 'p1' } } },
		)
		const ok = expectIssuedKey(result)
		expect(ok.token).toBe('px_svc')
		expect(ok.principalId).toBe('svc-1')
		expect(stub.issueKeyInputs[0]).toMatchObject({
			app: 'app-x',
			credential: 'px_ci',
			requestId: 'ray-3',
			service: { label: 'ci-bot', permissions: ['report.write'], scope: { type: 'project', value: 'p1' } },
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
			const stub = new IamRpcStub({ issueKey: { ok: false, reason: c.reason } })
			const result = await new IamClient(stub, 'app-x').issueKey(makeRequest(), { permissions: [] })
			expect(result.ok).toBe(false)
			if (result.ok) {
				throw new Error('unreachable')
			}
			expect(result.reason).toBe(c.reason)
			expect(result.status).toBe(c.status)
		}
	})
})

describe('IamClient.issueJwt', () => {
	test('ok → IssuedJwt and forwards the issuer credential + grants', async () => {
		const stub = new IamRpcStub({ issueJwt: { ok: true, token: 'eyJ.jwt', expiresAt: 123, id: 'tok-1' } })
		const result = await new IamClient(stub, 'app-x').issueJwt(
			makeRequest({ bearer: 'px_ci', ray: 'ray-4' }),
			{ permissions: [{ action: 'report.read', scope: null }], label: 'pass', ttl: 600 },
		)
		expect(result).toEqual({ ok: true, token: 'eyJ.jwt', expiresAt: 123, id: 'tok-1' })
		expect(stub.issueJwtInputs[0]).toEqual({
			app: 'app-x',
			credential: 'px_ci',
			requestId: 'ray-4',
			permissions: [{ action: 'report.read', scope: null }],
			label: 'pass',
			ttl: 600,
		})
	})

	test('failure → 403 (not_allowed)', async () => {
		const stub = new IamRpcStub({ issueJwt: { ok: false, reason: 'not_allowed' } })
		const result = await new IamClient(stub, 'app-x').issueJwt(makeRequest(), { permissions: [] })
		expect(result).toEqual({ ok: false, reason: 'not_allowed', status: 403 })
	})
})

describe('IamClient.revokeKey', () => {
	test('ok → forwards the caller credential + id, returns revoked flag', async () => {
		const stub = new IamRpcStub({ revokeKey: { ok: true, revoked: true } })
		const iam = new IamClient(stub, 'app-x')
		const result = await iam.revokeKey(makeRequest({ bearer: 'px_ci', ray: 'ray-9' }), 'cred-7')
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('unreachable')
		}
		expect(result.revoked).toBe(true)
		expect(stub.revokeKeyInputs[0]).toEqual({ app: 'app-x', credential: 'px_ci', requestId: 'ray-9', id: 'cred-7' })
	})

	test('already revoked → ok with revoked:false (idempotent)', async () => {
		const stub = new IamRpcStub({ revokeKey: { ok: true, revoked: false } })
		const result = await new IamClient(stub, 'app-x').revokeKey(makeRequest(), 'cred-7')
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
			const stub = new IamRpcStub({ revokeKey: { ok: false, reason: c.reason } })
			const result = await new IamClient(stub, 'app-x').revokeKey(makeRequest(), 'cred-7')
			expect(result.ok).toBe(false)
			if (result.ok) {
				throw new Error('unreachable')
			}
			expect(result.reason).toBe(c.reason)
			expect(result.status).toBe(c.status)
		}
	})
})
