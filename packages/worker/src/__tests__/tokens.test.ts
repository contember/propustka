import { parseTokenClaims, permits } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, jwtVerify } from 'jose'
import { hashToken } from '../capabilities'
import { getSigner } from '../signing'
import { mintToken } from '../tokens'
import { createHarness, seedInlineGrant, seedUser } from './helpers/harness'

const ENV = { PROPUSTKA_SIGNING_KEYS: '', ENVIRONMENT: 'local' }
const FUTURE = Math.floor(Date.now() / 1000) + 3600

/** Stand up a user + session + grant, returning what mint needs. */
async function setup(action = 'project.read', app = 'example-app') {
	const h = createHarness()
	const principalId = seedUser(h.sqlite, { sub: 'g-1', email: 'a@b.cz' })
	seedInlineGrant(h.sqlite, principalId, [action], null, app)
	const sessionToken = 'sess-cookie-value'
	await h.db.createSession({ tokenHash: await hashToken(sessionToken), principalId, idpSub: 'g-1', email: 'a@b.cz', expiresAt: FUTURE })
	return { h, principalId, sessionToken }
}

describe('mintToken', () => {
	test('mints a per-app token carrying the resolved permissions; the JWKS verifies it', async () => {
		const { h, principalId, sessionToken } = await setup()
		const services = h.makeServices({ issuer: 'https://propustka.test' })

		const { result, principalId: loggedId } = await mintToken(services, ENV, { app: 'example-app', session: sessionToken, requestId: 'r1' })
		expect(result.ok).toBe(true)
		expect(loggedId).toBe(principalId)
		if (!result.ok) {
			throw new Error('expected ok')
		}

		// Verify EXACTLY as the SDK will: local JWKS from the issuer's published keys, checking aud.
		const signer = await getSigner(ENV)
		const { payload } = await jwtVerify(result.token, createLocalJWKSet(signer.jwks()), {
			issuer: 'https://propustka.test',
			audience: 'example-app',
		})
		const claims = parseTokenClaims(payload)
		expect(claims?.kind).toBe('principal')
		if (claims?.kind !== 'principal') {
			throw new Error('expected principal claims')
		}
		expect(claims.sub).toBe(principalId)
		// The granted action is authorized by the same matcher the SDK's can() uses.
		expect(permits(claims.perms, 'project.read')).toBe(true)
		expect(permits(claims.perms, 'project.delete')).toBe(false)
	})

	test('resolves permissions PER APP — a grant on another app does not leak', async () => {
		const { h, sessionToken } = await setup('project.read', 'app-a')
		const services = h.makeServices({ issuer: 'https://propustka.test' })
		const { result } = await mintToken(services, ENV, { app: 'app-b', session: sessionToken, requestId: 'r' })
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected ok')
		}
		const claims = parseTokenClaims((await jwtVerify(result.token, createLocalJWKSet((await getSigner(ENV)).jwks()), { issuer: 'https://propustka.test', audience: 'app-b' })).payload)
		expect(claims?.kind === 'principal' && claims.perms).toEqual([])
	})

	test('no session → no_session', async () => {
		const h = createHarness()
		const { result } = await mintToken(h.makeServices(), ENV, { app: 'a', session: null, requestId: 'r' })
		expect(result).toEqual({ ok: false, reason: 'no_session' })
	})

	test('unknown/expired session → invalid_session', async () => {
		const h = createHarness()
		const { result } = await mintToken(h.makeServices(), ENV, { app: 'a', session: 'never-issued', requestId: 'r' })
		expect(result).toEqual({ ok: false, reason: 'invalid_session' })
	})

	test('disabled principal → disabled', async () => {
		const h = createHarness()
		const principalId = seedUser(h.sqlite, { sub: 'g-9', email: 'z@b.cz', disabled: true })
		const sessionToken = 'disabled-sess'
		await h.db.createSession({ tokenHash: await hashToken(sessionToken), principalId, idpSub: 'g-9', expiresAt: FUTURE })
		const { result, principalId: loggedId } = await mintToken(h.makeServices(), ENV, { app: 'a', session: sessionToken, requestId: 'r' })
		expect(result).toEqual({ ok: false, reason: 'disabled' })
		expect(loggedId).toBe(principalId)
	})
})
