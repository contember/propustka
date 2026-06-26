import { type AppGates, buildAccessClaims, type Jwks, type PermissionEntry } from '@propustka/core'
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

const HUMAN_GATES: AppGates = { rules: [{ path: '/*', kind: 'human' }] }
const SERVICE_GATES: AppGates = { rules: [{ path: '/*', kind: 'service' }] }
// service-then-human on the same glob — a machine key OR a logged-in human (the admin/gated-host shape).
const SERVICE_THEN_HUMAN: AppGates = { rules: [{ path: '/*', kind: 'service' }, { path: '/*', kind: 'human' }] }

async function signToken(key: KeyLike, ttlSeconds: number): Promise<string> {
	const now = Math.floor(Date.now() / 1000)
	const claims = buildAccessClaims({
		iss: ISSUER,
		app: APP,
		subject: 'user-1',
		type: 'user',
		label: 'a@b.cz',
		permissions: perms,
		issuedAt: now,
		expiresAt: now + ttlSeconds,
	})
	return new SignJWT({ ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(key)
}

function auth(binding: IamRpcStub, gates: AppGates = HUMAN_GATES): PropustkaAuth {
	return new PropustkaAuth(binding, APP, { issuer: ISSUER, gates })
}

const future = () => Math.floor(Date.now() / 1000) + 300

function request(cookie?: string, path = '/page'): Request {
	const headers = new Headers()
	if (cookie !== undefined) {
		headers.set('Cookie', cookie)
	}
	return new Request(`https://app.example.com${path}`, { headers })
}

function bearerRequest(token: string): Request {
	return new Request('https://app.example.com/api', { headers: { Authorization: `Bearer ${token}` } })
}

/** Sign an ANONYMOUS access token (no ptype) — what `issueJwt` / a standalone key produces. */
async function signAnon(key: KeyLike, ttlSeconds: number): Promise<string> {
	const now = Math.floor(Date.now() / 1000)
	const claims = buildAccessClaims({
		iss: ISSUER,
		app: APP,
		subject: 'cred-1',
		label: 'ci',
		permissions: perms,
		issuedAt: now,
		expiresAt: now + ttlSeconds,
	})
	return new SignJWT({ ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(key)
}

describe('PropustkaAuth — human gate, fast path (cached token)', () => {
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
		expect(result.context.principal?.id).toBe('user-1')
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

describe('PropustkaAuth — human gate, refresh path (mint from session)', () => {
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

describe('PropustkaAuth — human gate, unauthenticated', () => {
	test('no session → ok:false 401 with a login URL back to the current page', async () => {
		const binding = new IamRpcStub({ jwks: JWKS }) // mintToken → no_session
		const result = await auth(binding).authenticate(request())
		expect(result.ok).toBe(false)
		if (result.ok) {
			throw new Error('expected failure')
		}
		expect(result.reason).toBe('no_session')
		expect(result.status).toBe(401)
		expect(result.loginUrl).toBe(
			`${ISSUER}/auth/login?redirect=${encodeURIComponent('https://app.example.com/page')}`,
		)
	})

	test('an invalid session propagates the reason', async () => {
		const binding = new IamRpcStub({ jwks: JWKS, mintToken: { ok: false, reason: 'disabled' } })
		const result = await auth(binding).authenticate(request('px_session=zombie'))
		expect(result.ok).toBe(false)
		expect(result.ok === false && result.reason).toBe('disabled')
		expect(result.ok === false && result.loginUrl).toContain('/auth/login')
	})
})

describe('PropustkaAuth — service gate (machine bearer)', () => {
	test('a passthrough JWT verifies locally, anonymous principal, NO binding call', async () => {
		const binding = new IamRpcStub({ jwks: JWKS })
		const token = await signAnon(privateKey, 3600)
		const result = await auth(binding, SERVICE_GATES).authenticate(bearerRequest(token))
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected ok')
		}
		expect(result.context.principal).toBeNull()
		expect(result.context.can('demo.read')).toBe(true)
		expect(binding.mintFromKeyInputs).toHaveLength(0)
		expect(binding.mintTokenInputs).toHaveLength(0)
		expect(result.setCookie).toBeUndefined()
	})

	test('a px_ key is exchanged via mintFromKey, then cached (second request: no RPC)', async () => {
		const token = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintFromKey: { ok: true, token, expiresAt: Math.floor(Date.now() / 1000) + 300 } })
		const a = auth(binding, SERVICE_GATES)

		const r1 = await a.authenticate(bearerRequest('px_ci-key'))
		expect(r1.ok).toBe(true)
		expect(binding.mintFromKeyInputs).toHaveLength(1)
		expect(binding.mintFromKeyInputs[0]?.key).toBe('px_ci-key')

		// Same key again → authorizes off the cached token, no second mint.
		const r2 = await a.authenticate(bearerRequest('px_ci-key'))
		expect(r2.ok).toBe(true)
		expect(binding.mintFromKeyInputs).toHaveLength(1)
	})

	test('an unknown px_ key → ok:false 401 invalid_key, no loginUrl (machine)', async () => {
		const binding = new IamRpcStub({ jwks: JWKS }) // mintFromKey defaults to invalid_key
		const result = await auth(binding, SERVICE_GATES).authenticate(bearerRequest('px_nope'))
		expect(result.ok).toBe(false)
		if (result.ok) {
			throw new Error('expected failure')
		}
		expect(result.reason).toBe('invalid_key')
		expect(result.status).toBe(401)
		expect(result.loginUrl).toBeUndefined()
	})

	test('a garbage passthrough JWT → ok:false, NO binding call', async () => {
		const binding = new IamRpcStub({ jwks: JWKS })
		const result = await auth(binding, SERVICE_GATES).authenticate(bearerRequest('eyJnot.a.jwt'))
		expect(result.ok).toBe(false)
		expect(binding.mintFromKeyInputs).toHaveLength(0)
		expect(binding.mintTokenInputs).toHaveLength(0)
	})
})

describe('PropustkaAuth — service credential locations', () => {
	test('a px_ key in a declared header (path-matched) is resolved', async () => {
		const token = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintFromKey: { ok: true, token, expiresAt: future() } })
		const a = auth(binding, { rules: [{ path: '/api/v1/*', kind: 'service', credential: { in: 'header', name: 'x-opice-token' } }] })

		const result = await a.authenticate(new Request('https://app.example.com/api/v1/ingest', { headers: { 'x-opice-token': 'px_ci' } }))
		expect(result.ok).toBe(true)
		expect(binding.mintFromKeyInputs[0]?.key).toBe('px_ci')
	})

	test('a non-matching path matches no rule → 403, no resolution', async () => {
		const binding = new IamRpcStub({ jwks: JWKS })
		const a = auth(binding, { rules: [{ path: '/api/v1/*', kind: 'service', credential: { in: 'header', name: 'x-opice-token' } }] })

		const result = await a.authenticate(new Request('https://app.example.com/other', { headers: { 'x-opice-token': 'px_ci' } }))
		expect(result.ok).toBe(false)
		expect(result.ok === false && result.reason).toBe('no_rule')
		expect(result.ok === false && result.status).toBe(403)
		expect(binding.mintFromKeyInputs).toHaveLength(0)
	})

	test('a passthrough JWT in a declared query param verifies locally', async () => {
		const token = await signAnon(privateKey, 3600)
		const binding = new IamRpcStub({ jwks: JWKS })
		const a = auth(binding, { rules: [{ path: '/*', kind: 'service', credential: { in: 'query', name: 'pxt' } }] })

		const result = await a.authenticate(new Request(`https://app.example.com/x?pxt=${token}`))
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected ok')
		}
		expect(result.context.principal).toBeNull()
		expect(binding.mintFromKeyInputs).toHaveLength(0)
	})

	test('a header value may carry a Bearer prefix', async () => {
		const token = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintFromKey: { ok: true, token, expiresAt: future() } })
		const a = auth(binding, { rules: [{ path: '/*', kind: 'service', credential: { in: 'header', name: 'x-token' } }] })

		const result = await a.authenticate(new Request('https://app.example.com/x', { headers: { 'x-token': 'Bearer px_ci2' } }))
		expect(result.ok).toBe(true)
		expect(binding.mintFromKeyInputs[0]?.key).toBe('px_ci2')
	})
})

describe('PropustkaAuth — gate matching (public / no-rule / precedence)', () => {
	test('a public rule resolves an anonymous context with NO binding call', async () => {
		const binding = new IamRpcStub({ jwks: JWKS })
		const a = auth(binding, { rules: [{ path: '/public/*', kind: 'public' }, { path: '/*', kind: 'human' }] })

		const result = await a.authenticate(request(undefined, '/public/health'))
		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected ok')
		}
		expect(result.context.principal).toBeNull()
		expect(result.context.can('demo.read')).toBe(false) // anonymous → empty perms
		expect(binding.mintTokenInputs).toHaveLength(0)
		expect(binding.mintFromKeyInputs).toHaveLength(0)
	})

	test('a path matching no rule is denied (fail-closed 403)', async () => {
		const binding = new IamRpcStub({ jwks: JWKS })
		const a = auth(binding, { rules: [{ path: '/api/*', kind: 'service' }] })
		const result = await a.authenticate(request(undefined, '/elsewhere'))
		expect(result.ok).toBe(false)
		expect(result.ok === false && result.reason).toBe('no_rule')
		expect(result.ok === false && result.status).toBe(403)
	})

	test('service-then-human: a bearer wins', async () => {
		const token = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintFromKey: { ok: true, token, expiresAt: future() } })
		const result = await auth(binding, SERVICE_THEN_HUMAN).authenticate(bearerRequest('px_ci-key'))
		expect(result.ok).toBe(true)
		expect(binding.mintFromKeyInputs).toHaveLength(1)
		expect(binding.mintTokenInputs).toHaveLength(0)
	})

	test('service-then-human: no bearer falls through to the human rule (session)', async () => {
		const token = await signToken(privateKey, 300)
		const binding = new IamRpcStub({ jwks: JWKS, mintToken: { ok: true, token, expiresAt: future() } })
		const result = await auth(binding, SERVICE_THEN_HUMAN).authenticate(request('px_session=s'))
		expect(result.ok).toBe(true)
		expect(binding.mintFromKeyInputs).toHaveLength(0)
		expect(binding.mintTokenInputs).toHaveLength(1)
	})

	test('service-then-human: no bearer + no session → 401 with loginUrl', async () => {
		const binding = new IamRpcStub({ jwks: JWKS }) // mintToken → no_session
		const result = await auth(binding, SERVICE_THEN_HUMAN).authenticate(request())
		expect(result.ok).toBe(false)
		if (result.ok) {
			throw new Error('expected failure')
		}
		expect(result.reason).toBe('no_session')
		expect(result.loginUrl).toContain('/auth/login')
	})
})
