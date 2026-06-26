import { describe, expect, test } from 'bun:test'
import { IamClient } from '../client'
import { FakeIamClient } from '../fake'
import { IamRpcStub, makeRequest } from './stub'

// ── IamClient wrappers (forwarding + result/status mapping over the stub binding) ──

describe('IamClient.issueServiceToken', () => {
	test('ok → IssuedServiceToken; forwards app + credentials + grant spec', async () => {
		const stub = new IamRpcStub({ issueService: { ok: true, principalId: 'p1', clientId: 'cid', clientSecret: 'sec', tokenId: 'tid' } })
		const client = new IamClient(stub, 'opice')
		const res = await client.issueServiceToken(
			makeRequest({ token: 'jwt', ray: 'ray1' }),
			{ label: 'ingest:foo', permissions: ['report.write'], scope: { type: 'project', value: 'foo' } },
		)
		expect(res).toEqual({ ok: true, clientId: 'cid', clientSecret: 'sec', principalId: 'p1', tokenId: 'tid' })
		expect(stub.issueServiceInputs[0]).toMatchObject({
			app: 'opice',
			token: 'jwt',
			requestId: 'ray1',
			label: 'ingest:foo',
			permissions: ['report.write'],
			scope: { type: 'project', value: 'foo' },
		})
	})

	test('not_allowed → 403', async () => {
		const stub = new IamRpcStub({ issueService: { ok: false, reason: 'not_allowed' } })
		const res = await new IamClient(stub, 'opice').issueServiceToken(makeRequest({ token: 'jwt' }), { label: 'x', permissions: ['report.write'] })
		expect(res).toEqual({ ok: false, reason: 'not_allowed', status: 403 })
	})

	test('provisioning_failed → 502', async () => {
		const stub = new IamRpcStub({ issueService: { ok: false, reason: 'provisioning_failed' } })
		const res = await new IamClient(stub, 'opice').issueServiceToken(makeRequest({ token: 'jwt' }), { label: 'x', permissions: ['report.write'] })
		expect(res).toEqual({ ok: false, reason: 'provisioning_failed', status: 502 })
	})
})

describe('IamClient.revokeServiceToken / rotateServiceToken', () => {
	test('revoke ok → forwards principalId', async () => {
		const stub = new IamRpcStub({ revokeService: { ok: true, revoked: true } })
		const res = await new IamClient(stub, 'opice').revokeServiceToken(makeRequest({ token: 'jwt' }), 'p1')
		expect(res).toEqual({ ok: true, revoked: true })
		expect(stub.revokeServiceInputs[0]).toMatchObject({ app: 'opice', token: 'jwt', principalId: 'p1' })
	})

	test('revoke not_found → 404', async () => {
		const stub = new IamRpcStub({ revokeService: { ok: false, reason: 'not_found' } })
		const res = await new IamClient(stub, 'opice').revokeServiceToken(makeRequest({ token: 'jwt' }), 'nope')
		expect(res).toEqual({ ok: false, reason: 'not_found', status: 404 })
	})

	test('rotate ok → new secret', async () => {
		const stub = new IamRpcStub({ rotateService: { ok: true, clientId: 'cid', clientSecret: 'sec2', tokenId: 'tid' } })
		const res = await new IamClient(stub, 'opice').rotateServiceToken(makeRequest({ token: 'jwt' }), 'p1')
		expect(res).toEqual({ ok: true, clientId: 'cid', clientSecret: 'sec2', tokenId: 'tid' })
	})

	test('rotate provisioning_failed → 502', async () => {
		const stub = new IamRpcStub({ rotateService: { ok: false, reason: 'provisioning_failed' } })
		const res = await new IamClient(stub, 'opice').rotateServiceToken(makeRequest({ token: 'jwt' }), 'p1')
		expect(res).toEqual({ ok: false, reason: 'provisioning_failed', status: 502 })
	})
})

// ── FakeIamClient round-trip (local-dev machine auth without an Access edge) ──

const withClientId = (clientId: string): Request =>
	new Request('https://app.example.com/api/v1/foo/runs', { headers: { 'CF-Access-Client-Id': clientId } })

describe('FakeIamClient service tokens', () => {
	test('issue → authenticate by client id resolves a scoped service principal', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueServiceToken(makeRequest(), {
			label: 'ingest:foo',
			permissions: ['report.write'],
			scope: { type: 'project', value: 'foo' },
		})
		expect(issued.ok).toBe(true)
		if (!issued.ok) return

		const auth = await fake.authenticate(withClientId(issued.clientId))
		expect(auth.ok).toBe(true)
		if (!auth.ok) return
		expect(auth.principal?.type).toBe('service')
		expect(auth.can('report.write', { type: 'project', value: 'foo' })).toBe(true)
		expect(auth.can('report.write', { type: 'project', value: 'bar' })).toBe(false)
		expect(auth.can('report.read', { type: 'project', value: 'foo' })).toBe(false)
	})

	test('an unknown client id authenticates as unknown_principal (403)', async () => {
		const fake = new FakeIamClient()
		const auth = await fake.authenticate(withClientId('fake-client-nope'))
		expect(auth).toMatchObject({ ok: false, reason: 'unknown_principal', status: 403 })
	})

	test('revoke removes the principal (later auth 403) and is idempotent', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueServiceToken(makeRequest(), { label: 'x', permissions: ['report.read'], scope: { type: 'project', value: 'p' } })
		if (!issued.ok) throw new Error('issue failed')

		expect(await fake.revokeServiceToken(makeRequest(), issued.principalId)).toEqual({ ok: true, revoked: true })
		expect(await fake.revokeServiceToken(makeRequest(), issued.principalId)).toEqual({ ok: true, revoked: false })
		expect((await fake.authenticate(withClientId(issued.clientId))).ok).toBe(false)
	})

	test('rotate keeps the client id + principal, swaps the secret, still authenticates', async () => {
		const fake = new FakeIamClient()
		const issued = await fake.issueServiceToken(makeRequest(), { label: 'x', permissions: ['report.read'], scope: { type: 'project', value: 'p' } })
		if (!issued.ok) throw new Error('issue failed')

		const rotated = await fake.rotateServiceToken(makeRequest(), issued.principalId)
		expect(rotated.ok).toBe(true)
		if (!rotated.ok) return
		expect(rotated.clientId).toBe(issued.clientId)
		expect(rotated.clientSecret).not.toBe(issued.clientSecret)
		expect((await fake.authenticate(withClientId(issued.clientId))).ok).toBe(true)
	})

	test('rotate/revoke of an unknown principal → not_found (404)', async () => {
		const fake = new FakeIamClient()
		expect(await fake.rotateServiceToken(makeRequest(), 'fake-service-nope')).toMatchObject({ ok: false, reason: 'not_found', status: 404 })
		expect(await fake.revokeServiceToken(makeRequest(), 'fake-service-nope')).toMatchObject({ ok: false, reason: 'not_found', status: 404 })
	})
})
