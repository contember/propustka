import { buildPrincipalClaims, type Jwks, type PermissionEntry } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from 'jose'
import { PropustkaAuth } from '../session'
import { IamRpcStub } from './stub'

const ISSUER = 'https://propustka.test'
const APP = 'example-app'
const perms: PermissionEntry[] = [{ action: 'demo.read', scope: null, source: 'grant' }]

// One ES256 key for the suite; the public half is what `getJwks` serves.
const { publicKey, privateKey } = await generateKeyPair('ES256')
const pub = await exportJWK(publicKey)
const JWKS: Jwks = { keys: [{ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, kid: 'k1', alg: 'ES256', use: 'sig' }] }

async function signToken(key: KeyLike, ttlSeconds: number): Promise<string> {
	const now = Math.floor(Date.now() / 1000)
	const claims = buildPrincipalClaims({
		iss: ISSUER,
		app: APP,
		principalId: 'user-1',
		type: 'user',
		label: 'a@b.cz',
		permissions: perms,
		issuedAt: now,
		expiresAt: now + ttlSeconds,
	})
	return new SignJWT({ ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(key)
}

function auth(binding: IamRpcStub): PropustkaAuth {
	return new PropustkaAuth(binding, APP, { issuer: ISSUER })
}

function request(cookie?: string): Request {
	const headers = new Headers()
	if (cookie !== undefined) {
		headers.set('Cookie', cookie)
	}
	return new Request('https://app.example.com/page', { headers })
}

describe('PropustkaAuth — fast path (cached token)', () => {
	test('a valid px_token authorizes locally with NO binding call', async () => {
		const binding = new IamRpcStub({ jwks: JWKS })
		const token = await signToken(privateKey, 3600)

		const result = await auth(binding).authenticate(request(`px_token=${token}`))
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected ok')
		}
		expect(result.context.can('demo.read')).toBe(true)
		expect(result.context.can('demo.write')).toBe(false)
		expect(result.context.principal.id).toBe('user-1')
		// The whole point: no mint round-trip on the hot path, no fresh cookie.
		expect(binding.mintTokenInputs).toHaveLength(0)
		expect(result.setCookie).toBeUndefined()
	})

	test('a tampered/garbage token falls through to the (failing) mint path', async () => {
		const binding = new IamRpcStub({ jwks: JWKS }) // mintToken defaults to no_session
		const result = await auth(binding).authenticate(request('px_token=not.a.jwt'))
		expect(result.ok).toBe(false)
		expect(binding.mintTokenInputs).toHaveLength(1)
	})
})

describe('PropustkaAuth — refresh path (mint from session)', () => {
	test('no token → mints from the session cookie and returns a Set-Cookie', async () => {
		const token = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintToken: { ok: true, token, expiresAt: Math.floor(Date.now() / 1000) + 300 } })

		const result = await auth(binding).authenticate(request('px_session=sess-abc'))
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected ok')
		}
		expect(binding.mintTokenInputs[0]?.session).toBe('sess-abc')
		expect(binding.mintTokenInputs[0]?.app).toBe(APP)
		expect(result.context.can('demo.read')).toBe(true)
		expect(result.setCookie).toContain('px_token=')
		expect(result.setCookie).toContain('HttpOnly')
		expect(result.setCookie).toContain('Secure') // request is https
	})

	test('a near-expiry token is refreshed ahead of expiry', async () => {
		const nearlyExpired = await signToken(privateKey, 10) // < TOKEN_REFRESH_SKEW_SECONDS
		const fresh = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintToken: { ok: true, token: fresh, expiresAt: Math.floor(Date.now() / 1000) + 300 } })

		const result = await auth(binding).authenticate(request(`px_token=${nearlyExpired}; px_session=s`))
		expect(result.ok).toBe(true)
		expect(binding.mintTokenInputs).toHaveLength(1)
	})
})

describe('PropustkaAuth — unauthenticated', () => {
	test('no session → ok:false with a login URL back to the current page', async () => {
		const binding = new IamRpcStub({ jwks: JWKS }) // mintToken → no_session
		const result = await auth(binding).authenticate(request())
		expect(result.ok).toBe(false)
		if (result.ok) {
			throw new Error('expected failure')
		}
		expect(result.reason).toBe('no_session')
		expect(result.loginUrl).toBe(
			`${ISSUER}/auth/login?redirect=${encodeURIComponent('https://app.example.com/page')}`,
		)
	})

	test('an invalid session propagates the reason', async () => {
		const binding = new IamRpcStub({ jwks: JWKS, mintToken: { ok: false, reason: 'disabled' } })
		const result = await auth(binding).authenticate(request('px_session=zombie'))
		expect(result.ok).toBe(false)
		expect(result.ok === false && result.reason).toBe('disabled')
	})
})
