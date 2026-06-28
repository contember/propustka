import { buildAccessClaims, type Jwks, type PermissionEntry, type Scope } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { exportJWK, generateKeyPair, type KeyLike, SignJWT } from 'jose'
import { createIam, type IamEnv, makeDevContext, type PersonaSpec } from '../iam'
import type { AuthContext } from '../types'
import { IamRpcStub } from './stub'

const ISSUER = 'https://propustka.test'
const APP = 'example-app'

// One ES256 key for the suite; the public half is what the stub's `getJwks` serves.
const { publicKey, privateKey } = await generateKeyPair('ES256')
const pub = await exportJWK(publicKey)
const JWKS: Jwks = { keys: [{ kty: 'EC', crv: 'P-256', x: pub.x, y: pub.y, kid: 'k1', alg: 'ES256', use: 'sig' }] }

const now = () => Math.floor(Date.now() / 1000)

async function signUser(key: KeyLike, perms: PermissionEntry[], ttl = 3600): Promise<string> {
	const claims = buildAccessClaims({
		iss: ISSUER,
		app: APP,
		subject: 'user-1',
		type: 'user',
		label: 'a@b.cz',
		permissions: perms,
		issuedAt: now(),
		expiresAt: now() + ttl,
	})
	return new SignJWT({ ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(key)
}

async function signAnon(key: KeyLike, perms: PermissionEntry[], ttl = 3600): Promise<string> {
	const claims = buildAccessClaims({
		iss: ISSUER,
		app: APP,
		subject: 'cred-1',
		label: 'share',
		permissions: perms,
		issuedAt: now(),
		expiresAt: now() + ttl,
	})
	return new SignJWT({ ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(key)
}

/** Run a middleware through a tiny pipeline; the downstream stamps `seenAuth` so tests can assert ctx. */
interface Ctx {
	auth?: AuthContext | null
}
async function run(
	mw: (request: Request, ctx: Ctx, next: () => Promise<Response>) => Promise<Response>,
	request: Request,
	downstream: (ctx: Ctx) => Response = () => new Response('ok', { status: 200 }),
): Promise<{ response: Response; ctx: Ctx; nextCalled: boolean }> {
	const ctx: Ctx = {}
	let nextCalled = false
	const response = await mw(request, ctx, () => {
		nextCalled = true
		return Promise.resolve(downstream(ctx))
	})
	return { response, ctx, nextCalled }
}

const PERMS: PermissionEntry[] = [{ action: 'demo.read', scope: null, source: 'grant' }]

const PERSONAS: Record<string, PersonaSpec> = {
	'admin@x.test': { id: 'p-admin', label: 'admin@x.test', type: 'user', permissions: [{ action: '*', scope: null }] },
	'scoped@x.test': {
		id: 'p-scoped',
		label: 'scoped@x.test',
		type: 'user',
		permissions: [{ action: 'project.read', scope: { type: 'project', value: 'p1' } }],
	},
}

const offLocalEnv = (stub: IamRpcStub): IamEnv => ({ IAM: stub, PROPUSTKA_URL: ISSUER, PROPUSTKA_APP_ID: APP })
const devEnv: IamEnv = { DEV: 'true', PROPUSTKA_APP_ID: APP }

// ── createIam ────────────────────────────────────────────────────────────────────

describe('createIam', () => {
	test('off-local builds an IamClient-backed Iam and delegates listPrincipals', async () => {
		const stub = new IamRpcStub({ listPrincipals: { ok: true, principals: [] }, jwks: JWKS })
		const iam = createIam(offLocalEnv(stub))
		await iam.listPrincipals(new Request('https://app/x', { headers: { Authorization: 'Bearer px_ci' } }))
		expect(stub.listPrincipalsInputs[0]?.app).toBe(APP)
	})

	test('dev builds a FakeIamClient whose listPrincipals enumerates the personas', async () => {
		const iam = createIam(devEnv, { devPersonas: PERSONAS })
		const result = await iam.listPrincipals(new Request('https://app/x'))
		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.principals.map((p) => p.id).sort()).toEqual(['p-admin', 'p-scoped'])
	})

	test('appId resolves from opts.appId over env', () => {
		const stub = new IamRpcStub()
		const iam = createIam({ IAM: stub, PROPUSTKA_URL: ISSUER, PROPUSTKA_APP_ID: 'env-app' }, { appId: 'opt-app' })
		expect(iam).toBeDefined() // appId is private; exercised via the binding inputs in other tests
	})

	test('throws when no app id is resolvable', () => {
		expect(() => createIam({ DEV: 'true' })).toThrow(/app id is required/)
	})

	test('off-local throws when the IAM binding is missing', () => {
		expect(() => createIam({ PROPUSTKA_URL: ISSUER, PROPUSTKA_APP_ID: APP })).toThrow(/IAM service binding is missing/)
	})

	test('off-local throws when PROPUSTKA_URL is missing', () => {
		expect(() => createIam({ IAM: new IamRpcStub(), PROPUSTKA_APP_ID: APP })).toThrow(/PROPUSTKA_URL is missing/)
	})
})

// ── makeDevContext ─────────────────────────────────────────────────────────────────

describe('makeDevContext', () => {
	test('can/scopedTo evaluate against the persona permissions (permits semantics)', () => {
		const ctx = makeDevContext(PERSONAS['scoped@x.test']!)
		expect(ctx.principal?.id).toBe('p-scoped')
		expect(ctx.principal?.type).toBe('user')
		expect(ctx.can('project.read', { type: 'project', value: 'p1' })).toBe(true)
		expect(ctx.can('project.read', { type: 'project', value: 'p2' })).toBe(false)
		expect(ctx.can('project.read')).toBe(false) // scope-less needs a global grant
		expect(ctx.scopedTo('project.read', 'project')).toEqual(['p1'])
	})

	test('a global wildcard persona is unrestricted', () => {
		const ctx = makeDevContext(PERSONAS['admin@x.test']!)
		expect(ctx.can('anything.at.all')).toBe(true)
		expect(ctx.scopedTo('anything', 'project')).toBeNull()
	})

	test('a non-"service" type resolves to user; "service" is preserved', () => {
		expect(makeDevContext({ id: 's', label: 's', type: 'robot', permissions: [] }).principal?.type).toBe('user')
		expect(makeDevContext({ id: 's', label: 's', type: 'service', permissions: [] }).principal?.type).toBe('service')
	})

	test('audit is a no-op', async () => {
		await expect(makeDevContext(PERSONAS['admin@x.test']!).audit({ action: 'x', resourceType: 'y' })).resolves.toBeUndefined()
	})
})

// ── authMiddleware — success ─────────────────────────────────────────────────────

const HUMAN_GATES = { rules: [{ path: '/*', kind: 'human' as const }] }
const SERVICE_GATES = { rules: [{ path: '/*', kind: 'service' as const }] }

describe('authMiddleware — success', () => {
	test('a valid px_token sets ctx.auth and calls next (no Set-Cookie)', async () => {
		const stub = new IamRpcStub({ jwks: JWKS })
		const token = await signUser(privateKey, PERMS)
		const iam = createIam(offLocalEnv(stub))
		const { response, ctx, nextCalled } = await run(
			iam.authMiddleware({ gates: HUMAN_GATES }),
			new Request('https://app/page', { headers: { Cookie: `px_token=${token}` } }),
		)
		expect(nextCalled).toBe(true)
		expect(response.status).toBe(200)
		expect(ctx.auth?.can('demo.read')).toBe(true)
		expect(ctx.auth?.principal?.id).toBe('user-1')
		expect(response.headers.get('set-cookie')).toBeNull()
		expect(stub.mintTokenInputs).toHaveLength(0)
	})

	test('a minted token is appended as Set-Cookie on the downstream response', async () => {
		const token = await signUser(privateKey, PERMS, 300)
		const stub = new IamRpcStub({ jwks: JWKS, mintToken: { ok: true, token, expiresAt: now() + 300 } })
		const iam = createIam(offLocalEnv(stub))
		const { response, nextCalled } = await run(
			iam.authMiddleware({ gates: HUMAN_GATES }),
			new Request('https://app/page', { headers: { Cookie: 'px_session=sess-1' } }),
		)
		expect(nextCalled).toBe(true)
		expect(response.status).toBe(200)
		expect(response.headers.get('set-cookie')).toContain('px_token=')
	})
})

// ── authMiddleware — human miss (content negotiation) ────────────────────────────

describe('authMiddleware — human miss', () => {
	test('a document navigation (Accept: text/html) → 302 to the login URL, next NOT called', async () => {
		const stub = new IamRpcStub({ jwks: JWKS }) // mintToken → no_session
		const iam = createIam(offLocalEnv(stub))
		const { response, nextCalled } = await run(
			iam.authMiddleware({ gates: HUMAN_GATES }),
			new Request('https://app/page', { headers: { Accept: 'text/html' } }),
		)
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(302)
		expect(response.headers.get('location')).toContain(`${ISSUER}/auth/login?redirect=`)
	})

	test('an XHR/RPC request → 401 JSON { error: { type: auth, message, loginUrl } }', async () => {
		const stub = new IamRpcStub({ jwks: JWKS })
		const iam = createIam(offLocalEnv(stub))
		const { response, nextCalled } = await run(
			iam.authMiddleware({ gates: HUMAN_GATES }),
			new Request('https://app/page', { headers: { Accept: 'application/json' } }),
		)
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(401)
		const body = await response.json() as { error: { type: string; message: string; loginUrl: string } }
		expect(body.error.type).toBe('auth')
		expect(body.error.loginUrl).toContain('/auth/login')
		expect(typeof body.error.message).toBe('string')
	})
})

// ── authMiddleware — other failure ───────────────────────────────────────────────

describe('authMiddleware — service failure (no loginUrl)', () => {
	test('an invalid px_ key → status + JSON { error: { type: reason, message } }', async () => {
		const stub = new IamRpcStub({ jwks: JWKS }) // mintFromKey → invalid_key
		const iam = createIam(offLocalEnv(stub))
		const { response, nextCalled } = await run(
			iam.authMiddleware({ gates: SERVICE_GATES }),
			new Request('https://app/api', { headers: { Authorization: 'Bearer px_nope' } }),
		)
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(401)
		const body = await response.json() as { error: { type: string; message: string; loginUrl?: string } }
		expect(body.error.type).toBe('invalid_key')
		expect(body.error.loginUrl).toBeUndefined()
	})

	test('a no-rule path → 403 JSON', async () => {
		const stub = new IamRpcStub({ jwks: JWKS })
		const iam = createIam(offLocalEnv(stub))
		const { response } = await run(
			iam.authMiddleware({ gates: { rules: [{ path: '/api/*', kind: 'service' }] } }),
			new Request('https://app/elsewhere'),
		)
		expect(response.status).toBe(403)
		const body = await response.json() as { error: { type: string } }
		expect(body.error.type).toBe('no_rule')
	})

	test('onError can override a failure', async () => {
		const stub = new IamRpcStub({ jwks: JWKS })
		const iam = createIam(offLocalEnv(stub))
		const { response } = await run(
			iam.authMiddleware({ gates: SERVICE_GATES, onError: () => new Response('custom', { status: 418 }) }),
			new Request('https://app/api', { headers: { Authorization: 'Bearer px_nope' } }),
		)
		expect(response.status).toBe(418)
		expect(await response.text()).toBe('custom')
	})
})

// ── authMiddleware — dev persona ─────────────────────────────────────────────────

describe('authMiddleware — dev persona', () => {
	const iam = () => createIam(devEnv, { devPersonas: PERSONAS, devDefaultPersona: 'admin@x.test' })

	test('the ?__as= query selects a persona', async () => {
		const { ctx, nextCalled } = await run(iam().authMiddleware({ gates: HUMAN_GATES }), new Request('https://app/page?__as=scoped@x.test'))
		expect(nextCalled).toBe(true)
		expect(ctx.auth?.principal?.id).toBe('p-scoped')
	})

	test('the persona cookie selects a persona', async () => {
		const { ctx } = await run(
			iam().authMiddleware({ gates: HUMAN_GATES }),
			new Request('https://app/page', { headers: { Cookie: 'propustka_dev_principal=scoped@x.test' } }),
		)
		expect(ctx.auth?.principal?.id).toBe('p-scoped')
	})

	test('the persona cookie is URL-decoded (devLoginHandler round-trip)', async () => {
		const { ctx } = await run(
			iam().authMiddleware({ gates: HUMAN_GATES }),
			new Request('https://app/page', { headers: { Cookie: 'propustka_dev_principal=admin%40x.test' } }),
		)
		expect(ctx.auth?.principal?.id).toBe('p-admin')
	})

	test('no selector falls back to the default persona', async () => {
		const { ctx } = await run(iam().authMiddleware({ gates: HUMAN_GATES }), new Request('https://app/page'))
		expect(ctx.auth?.principal?.id).toBe('p-admin')
	})

	test('an unknown persona → 403, next NOT called', async () => {
		const { response, nextCalled } = await run(iam().authMiddleware({ gates: HUMAN_GATES }), new Request('https://app/page?__as=ghost@x.test'))
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(403)
		const body = await response.json() as { error: { type: string } }
		expect(body.error.type).toBe('unknown_principal')
	})
})

// ── apiKeyMiddleware ─────────────────────────────────────────────────────────────

describe('apiKeyMiddleware', () => {
	const iam = () => createIam(devEnv, { devPersonas: PERSONAS })

	test('a Bearer key resolves to a permissive machine context', async () => {
		const mw = iam().apiKeyMiddleware({ resolve: (key) => Promise.resolve(key === 'k-good' ? { id: 'svc-1', label: 'ci' } : null) })
		const { ctx, nextCalled } = await run(mw, new Request('https://app/ingest', { headers: { Authorization: 'Bearer k-good' } }))
		expect(nextCalled).toBe(true)
		expect(ctx.auth?.principal).toEqual({ id: 'svc-1', type: 'service', label: 'ci' })
		expect(ctx.auth?.can('anything')).toBe(true) // the key IS the authorization
		expect(ctx.auth?.scopedTo('anything', 'project')).toBeNull()
	})

	test('an X-Sentry-Auth sentry_key= list is parsed', async () => {
		const seen: string[] = []
		const mw = iam().apiKeyMiddleware({
			resolve: (key) => {
				seen.push(key)
				return Promise.resolve({ id: 's', label: 's' })
			},
		})
		await run(mw, new Request('https://app/ingest', { headers: { 'X-Sentry-Auth': 'Sentry sentry_version=7, sentry_key=abc123, sentry_client=x' } }))
		expect(seen[0]).toBe('abc123')
	})

	test('a ?sentry_key= query param is read', async () => {
		const seen: string[] = []
		const mw = iam().apiKeyMiddleware({
			resolve: (key) => {
				seen.push(key)
				return Promise.resolve({ id: 's', label: 's' })
			},
		})
		await run(mw, new Request('https://app/ingest?sentry_key=q-key'))
		expect(seen[0]).toBe('q-key')
	})

	test('a custom header + query are configurable', async () => {
		const seen: string[] = []
		const mw = iam().apiKeyMiddleware({
			header: 'X-Api-Key',
			query: 'k',
			resolve: (key) => {
				seen.push(key)
				return Promise.resolve({ id: 's', label: 's' })
			},
		})
		await run(mw, new Request('https://app/x', { headers: { 'X-Api-Key': 'raw-key' } }))
		expect(seen[0]).toBe('raw-key')
	})

	test('a missing key → 401 JSON, next NOT called', async () => {
		const mw = iam().apiKeyMiddleware({ resolve: () => Promise.resolve({ id: 's', label: 's' }) })
		const { response, nextCalled } = await run(mw, new Request('https://app/ingest'))
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(401)
		expect((await response.json() as { error: { type: string } }).error.type).toBe('auth')
	})

	test('a null resolve → 401 JSON', async () => {
		const mw = iam().apiKeyMiddleware({ resolve: () => Promise.resolve(null) })
		const { response, nextCalled } = await run(mw, new Request('https://app/ingest', { headers: { Authorization: 'Bearer bad' } }))
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(401)
	})
})

// ── capabilityMiddleware ─────────────────────────────────────────────────────────

const CAP_PERMS: PermissionEntry[] = [{ action: 'report.read', scope: { type: 'run', value: 'r1' } as Scope, source: 'grant' }]

describe('capabilityMiddleware — off-local', () => {
	test('a ?token= redeems via mintFromKey into an anonymous, exact-resource context', async () => {
		const token = await signAnon(privateKey, CAP_PERMS)
		const stub = new IamRpcStub({ jwks: JWKS, mintFromKey: { ok: true, token, expiresAt: now() + 300 } })
		const iam = createIam(offLocalEnv(stub))
		const { ctx, nextCalled } = await run(iam.capabilityMiddleware(), new Request('https://app/s/run?token=px_share'))
		expect(nextCalled).toBe(true)
		expect(stub.mintFromKeyInputs[0]?.key).toBe('px_share')
		expect(ctx.auth?.principal).toBeNull()
		expect(ctx.auth?.can('report.read', { type: 'run', value: 'r1' })).toBe(true)
		expect(ctx.auth?.can('report.read', { type: 'run', value: 'r2' })).toBe(false)
	})

	test('the token can ride the configured cookie', async () => {
		const token = await signAnon(privateKey, CAP_PERMS)
		const stub = new IamRpcStub({ jwks: JWKS, mintFromKey: { ok: true, token, expiresAt: now() + 300 } })
		const iam = createIam(offLocalEnv(stub))
		const { ctx } = await run(
			iam.capabilityMiddleware({ cookie: 'opice_read' }),
			new Request('https://app/s/run', { headers: { Cookie: 'opice_read=px_share' } }),
		)
		expect(ctx.auth?.can('report.read', { type: 'run', value: 'r1' })).toBe(true)
	})

	test('no token → 404, next NOT called', async () => {
		const stub = new IamRpcStub({ jwks: JWKS })
		const iam = createIam(offLocalEnv(stub))
		const { response, nextCalled } = await run(iam.capabilityMiddleware(), new Request('https://app/s/run'))
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(404)
	})

	test('a failed redeem → 404 (never a leaky 401/403)', async () => {
		const stub = new IamRpcStub({ jwks: JWKS }) // mintFromKey → invalid_key
		const iam = createIam(offLocalEnv(stub))
		const { response, nextCalled } = await run(iam.capabilityMiddleware(), new Request('https://app/s/run?token=px_bad'))
		expect(nextCalled).toBe(false)
		expect(response.status).toBe(404)
	})
})

describe('capabilityMiddleware — dev', () => {
	test('a present token grants an open context', async () => {
		const iam = createIam(devEnv, { devPersonas: PERSONAS })
		const { ctx, nextCalled } = await run(iam.capabilityMiddleware(), new Request('https://app/s/run?token=anything'))
		expect(nextCalled).toBe(true)
		expect(ctx.auth?.can('report.read', { type: 'run', value: 'whatever' })).toBe(true)
	})

	test('no token → 404 even in dev', async () => {
		const iam = createIam(devEnv, { devPersonas: PERSONAS })
		const { response } = await run(iam.capabilityMiddleware(), new Request('https://app/s/run'))
		expect(response.status).toBe(404)
	})
})

// ── devLoginHandler ──────────────────────────────────────────────────────────────

describe('devLoginHandler', () => {
	test('sets the persona cookie from ?as= and 302s to /', () => {
		const iam = createIam(devEnv, { devPersonas: PERSONAS })
		const response = iam.devLoginHandler()(new Request('https://app/__dev/login?as=admin@x.test'))
		expect(response.status).toBe(302)
		expect(response.headers.get('location')).toBe('/')
		expect(response.headers.get('set-cookie')).toContain('propustka_dev_principal=admin%40x.test')
	})

	test('honours a custom persona cookie name', () => {
		const iam = createIam(devEnv, { devPersonas: PERSONAS, devPersonaCookie: 'my_dev' })
		const response = iam.devLoginHandler()(new Request('https://app/__dev/login?as=x'))
		expect(response.headers.get('set-cookie')).toContain('my_dev=x')
	})
})
