import { parseAccessClaims, type PermissionEntry, permits, type Scope } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, jwtVerify } from 'jose'
import { issueJwt, issueKey } from '../issue'
import { hashToken } from '../secret'
import { getSigner } from '../signing'
import { mintFromKey } from '../tokens'
import { createHarness, seedInlineGrant, seedService, seedUser } from './helpers/harness'

const ENV = { PROPUSTKA_SIGNING_KEYS: '', ENVIRONMENT: 'local' }
const ISSUER = 'https://propustka.test'

function perm(action: string, scope: Scope | null = null): PermissionEntry {
	return { action, scope, source: 'grant' }
}

/** Verify a minted token EXACTLY as the SDK will: a local JWKS over the issuer's published keys. */
async function verify(token: string, app: string) {
	const signer = await getSigner(ENV)
	const { payload } = await jwtVerify(token, createLocalJWKSet(signer.jwks()), { issuer: ISSUER, audience: app })
	return parseAccessClaims(payload)
}

describe('issueKey → mintFromKey (standalone, frozen inline grants)', () => {
	test('mints an anonymous access token carrying the frozen scoped grant', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issuerId = seedUser(h.sqlite, { sub: 'iss', email: 'iss@contember.com' })
		const issuer = { id: issuerId, permissions: [perm('report.write')] } // holds it globally → may delegate scoped

		const issued = await issueKey(
			services,
			{
				app: 'opice',
				token: null,
				cookie: null,
				origin: null,
				requestId: 'r1',
				permissions: [{ action: 'report.write', scope: { type: 'project', value: 'demo' } }],
				label: 'opice CI',
			},
			issuer,
			'opice',
		)
		expect(issued.result.ok).toBe(true)
		if (!issued.result.ok) throw new Error('expected ok')
		expect(issued.result.token.startsWith('px_')).toBe(true)

		const { result, credentialId } = await mintFromKey(services, ENV, { app: 'opice', key: issued.result.token, requestId: 'r2' })
		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(credentialId).toBe(issued.result.id)

		const claims = await verify(result.token, 'opice')
		expect(claims?.ptype).toBeUndefined() // anonymous — no principal
		expect(claims?.sub).toBe(issued.result.id)
		expect(permits(claims?.perms ?? [], 'report.write', { type: 'project', value: 'demo' })).toBe(true)
		expect(permits(claims?.perms ?? [], 'report.write', { type: 'project', value: 'other' })).toBe(false)
	})

	test('a credential granting nothing is refused at issue', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issuerId = seedUser(h.sqlite, { sub: 'iss2', email: 'iss2@contember.com' })
		const issued = await issueKey(services, { app: 'a', token: null, cookie: null, origin: null, requestId: 'r' }, {
			id: issuerId,
			permissions: [perm('*')],
		}, 'a')
		expect(issued.result).toEqual({ ok: false, reason: 'not_allowed' })
	})

	test('delegation: an issuer cannot mint a key beyond its own permissions', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issued = await issueKey(
			services,
			{
				app: 'a',
				token: null,
				cookie: null,
				origin: null,
				requestId: 'r',
				permissions: [{ action: 'report.delete' }],
			},
			{ id: seedUser(h.sqlite, { sub: 'iss3', email: 'iss3@contember.com' }), permissions: [perm('report.read')] },
			'a',
		)
		expect(issued.result).toEqual({ ok: false, reason: 'not_allowed' })
	})
})

describe('issueKey → mintFromKey (principal-bound)', () => {
	test('a self-bound key carries the principal LIVE resolved permissions', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const svcId = seedService(h.sqlite, { commonName: 'svc-cn', label: 'svc' })
		seedInlineGrant(h.sqlite, svcId, ['project.read'], null, 'app-x')

		const issued = await issueKey(
			services,
			{
				app: 'app-x',
				token: null,
				cookie: null,
				origin: null,
				requestId: 'r',
				principalId: svcId,
			},
			{ id: svcId, permissions: [perm('project.read')] },
			'app-x',
		)
		expect(issued.result.ok).toBe(true)
		if (!issued.result.ok) throw new Error('expected ok')

		const { result } = await mintFromKey(services, ENV, { app: 'app-x', key: issued.result.token, requestId: 'r2' })
		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		const claims = await verify(result.token, 'app-x')
		expect(claims?.ptype).toBe('service')
		expect(claims?.sub).toBe(svcId)
		expect(permits(claims?.perms ?? [], 'project.read')).toBe(true)
	})

	test('inline grants DOWNSCOPE a bound key (effective = principal ∩ inline)', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const svcId = seedService(h.sqlite, { commonName: 'svc-2' })
		seedInlineGrant(h.sqlite, svcId, ['project.read', 'project.write'], null, 'app-x')

		const issued = await issueKey(
			services,
			{
				app: 'app-x',
				token: null,
				cookie: null,
				origin: null,
				requestId: 'r',
				principalId: svcId,
				permissions: [{ action: 'project.read' }], // downscope to read-only
			},
			{ id: svcId, permissions: [perm('project.read'), perm('project.write')] },
			'app-x',
		)
		expect(issued.result.ok).toBe(true)
		if (!issued.result.ok) throw new Error('expected ok')

		const { result } = await mintFromKey(services, ENV, { app: 'app-x', key: issued.result.token, requestId: 'r2' })
		if (!result.ok) throw new Error('expected ok')
		const claims = await verify(result.token, 'app-x')
		expect(permits(claims?.perms ?? [], 'project.read')).toBe(true)
		expect(permits(claims?.perms ?? [], 'project.write')).toBe(false) // dropped by the downscope
	})

	test('binding to ANOTHER principal is refused (v1: self only)', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issued = await issueKey(
			services,
			{
				app: 'a',
				token: null,
				cookie: null,
				origin: null,
				requestId: 'r',
				principalId: 'someone-else',
			},
			{ id: seedUser(h.sqlite, { sub: 'me', email: 'me@contember.com' }), permissions: [perm('*')] },
			'a',
		)
		expect(issued.result).toEqual({ ok: false, reason: 'not_allowed' })
	})
})

describe('issueKey service mode (folded service token)', () => {
	test('creates a fresh service principal + grant, binds the key, mintFromKey resolves its perms', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issuerId = seedUser(h.sqlite, { sub: 'iss-svc', email: 'iss@contember.com' })

		const issued = await issueKey(
			services,
			{
				app: 'opice',
				token: null,
				cookie: null,
				origin: null,
				requestId: 'r1',
				service: { label: 'opice CI', permissions: ['report.write'], scope: { type: 'project', value: 'demo' } },
			},
			{ id: issuerId, permissions: [perm('report.write')] }, // holds it globally → may delegate scoped
			'opice',
		)
		expect(issued.result.ok).toBe(true)
		if (!issued.result.ok) throw new Error('expected ok')
		expect(issued.result.token.startsWith('px_')).toBe(true)
		expect(issued.result.principalId).toBeTruthy()

		const { result } = await mintFromKey(services, ENV, { app: 'opice', key: issued.result.token, requestId: 'r2' })
		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		const claims = await verify(result.token, 'opice')
		expect(claims?.ptype).toBe('service')
		expect(claims?.sub).toBe(issued.result.principalId)
		expect(permits(claims?.perms ?? [], 'report.write', { type: 'project', value: 'demo' })).toBe(true)
		expect(permits(claims?.perms ?? [], 'report.write', { type: 'project', value: 'other' })).toBe(false)
	})

	test('delegation: a service grant beyond the issuer is refused', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issuerId = seedUser(h.sqlite, { sub: 'iss-svc2', email: 'iss2@contember.com' })
		const issued = await issueKey(
			services,
			{ app: 'a', token: null, cookie: null, origin: null, requestId: 'r', service: { label: 'x', permissions: ['report.delete'] } },
			{ id: issuerId, permissions: [perm('report.read')] },
			'a',
		)
		expect(issued.result).toEqual({ ok: false, reason: 'not_allowed' })
	})

	test('a service grant with no permissions is refused', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issuerId = seedUser(h.sqlite, { sub: 'iss-svc3', email: 'iss3@contember.com' })
		const issued = await issueKey(
			services,
			{ app: 'a', token: null, cookie: null, origin: null, requestId: 'r', service: { label: 'x', permissions: [] } },
			{ id: issuerId, permissions: [perm('*')] },
			'a',
		)
		expect(issued.result).toEqual({ ok: false, reason: 'not_allowed' })
	})
})

describe('mintFromKey failures', () => {
	test('an unknown key → invalid_key', async () => {
		const h = createHarness()
		const { result } = await mintFromKey(h.makeServices({ issuer: ISSUER }), ENV, { app: 'a', key: 'px_nope', requestId: 'r' })
		expect(result).toEqual({ ok: false, reason: 'invalid_key' })
	})

	test('a key bound to a disabled principal → disabled', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const svcId = seedService(h.sqlite, { commonName: 'svc-d', disabled: true })
		const key = 'px_live-key'
		await services.db.createCredential({ tokenHash: await hashToken(key), principalId: svcId, issuedBy: svcId, grants: [] })
		const { result } = await mintFromKey(services, ENV, { app: 'a', key, requestId: 'r' })
		expect(result).toEqual({ ok: false, reason: 'disabled' })
	})

	test('a revoked key no longer resolves', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const key = 'px_to-revoke'
		const issuerId = seedUser(h.sqlite, { sub: 'iss-rev', email: 'rev@contember.com' })
		const id = await services.db.createCredential({
			tokenHash: await hashToken(key),
			issuedBy: issuerId,
			grants: [{ action: 'x' }],
		})
		expect(await services.db.revokeCredential(id)).toBe(true)
		const { result } = await mintFromKey(services, ENV, { app: 'a', key, requestId: 'r' })
		expect(result).toEqual({ ok: false, reason: 'invalid_key' })
	})
})

describe('issueJwt (passthrough)', () => {
	test('signs a stateless anonymous token carrying the frozen grants', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issued = await issueJwt(services, ENV, {
			app: 'opice',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'r',
			permissions: [{ action: 'event.ingest' }],
			ttl: 3600,
			label: 'CI passthrough',
		}, { id: 'i', permissions: [perm('event.ingest')] })
		expect(issued.result.ok).toBe(true)
		if (!issued.result.ok) throw new Error('expected ok')
		expect(issued.result.token.startsWith('eyJ')).toBe(true)

		const claims = await verify(issued.result.token, 'opice')
		expect(claims?.ptype).toBeUndefined()
		expect(permits(claims?.perms ?? [], 'event.ingest')).toBe(true)
		// No DB row was written — it is audit-only.
		expect(await services.db.getCredentialById(issued.result.id)).toBeNull()
	})

	test('caps the requested ttl at the passthrough maximum', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const now = Math.floor(Date.now() / 1000)
		const issued = await issueJwt(services, ENV, {
			app: 'a',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'r',
			permissions: [{ action: 'x' }],
			ttl: 10 * 24 * 60 * 60, // 10 days — well over the 24h cap
		}, { id: 'i', permissions: [perm('x')] })
		if (!issued.result.ok) throw new Error('expected ok')
		expect(issued.result.expiresAt - now).toBeLessThanOrEqual(24 * 60 * 60 + 1)
	})

	test('delegation applies to passthrough too', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const issued = await issueJwt(services, ENV, {
			app: 'a',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'r',
			permissions: [{ action: 'secret.read' }],
		}, { id: 'i', permissions: [perm('public.read')] })
		expect(issued.result).toEqual({ ok: false, reason: 'not_allowed' })
	})
})
