import { SESSION_COOKIE } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { handleAuth } from '../auth/routes'
import { OidcClient, type OidcIdentity, type OidcMetadata } from '../oidc'
import { hashToken } from '../secret'
import { createHarness, type Harness, seedUser } from './helpers/harness'

const AUTH_ENV = { PROPUSTKA_SIGNING_KEYS: '', ENVIRONMENT: 'local' }
const ISSUER = 'http://localhost:18191'

function ctx(): ExecutionContext {
	return { waitUntil() {}, passThroughOnException() {}, props: {} }
}

/** Pull a single cookie's value out of a `Set-Cookie` header list. */
function setCookieValue(res: Response, name: string): string | null {
	for (const header of res.headers.getSetCookie()) {
		const eq = header.indexOf('=')
		if (header.slice(0, eq) === name) {
			return header.slice(eq + 1).split(';')[0] ?? null
		}
	}
	return null
}

const IDP_METADATA: OidcMetadata = {
	issuer: 'https://idp.test',
	authorizationEndpoint: 'https://idp.test/authorize',
	tokenEndpoint: 'https://idp.test/token',
	jwksUri: 'https://idp.test/jwks',
}

/** An OidcClient that skips the network: discovery injected, fixed identity from the exchange/verify. */
class FakeOidc extends OidcClient {
	constructor(private readonly identity: OidcIdentity | null) {
		super(
			{ issuer: 'https://idp.test', clientId: 'x', clientSecret: 'y', redirectUri: `${ISSUER}/auth/callback`, scopes: '', requireVerifiedEmail: true },
			{ metadata: IDP_METADATA },
		)
	}
	override async exchangeCode(): Promise<string | null> {
		return 'fake-id-token'
	}
	override async verifyIdToken(): Promise<OidcIdentity | null> {
		return this.identity
	}
}

describe('GET /.well-known/jwks.json', () => {
	test('serves the public key set', async () => {
		const h = createHarness()
		const res = await handleAuth(new Request(`${ISSUER}/.well-known/jwks.json`), h.makeServices(), AUTH_ENV, ctx())
		expect(res.status).toBe(200)
		const body: unknown = await res.json()
		const keys = body && typeof body === 'object' && 'keys' in body ? body.keys : undefined
		expect(Array.isArray(keys) && keys.length).toBeGreaterThan(0)
	})
})

describe('GET /auth/login', () => {
	test('302s to the IdP with PKCE and sets the in-flight cookie', async () => {
		const h = createHarness()
		const res = await handleAuth(
			new Request(`${ISSUER}/auth/login?redirect=${encodeURIComponent(`${ISSUER}/back`)}`),
			h.makeServices({ issuer: ISSUER }),
			AUTH_ENV,
			ctx(),
		)
		expect(res.status).toBe(302)
		const location = new URL(res.headers.get('location') ?? '')
		expect(location.hostname).toBe('idp.test')
		expect(location.searchParams.get('code_challenge_method')).toBe('S256')
		expect(setCookieValue(res, 'px_oidc')).toBeTruthy()
	})

	test('rejects an open-redirect target, falling back to the issuer', async () => {
		const h = createHarness()
		const res = await handleAuth(
			new Request(`${ISSUER}/auth/login?redirect=${encodeURIComponent('https://evil.example/x')}`),
			h.makeServices({ issuer: ISSUER }),
			AUTH_ENV,
			ctx(),
		)
		// The bad redirect is dropped; login still proceeds (the redirect is only used post-callback).
		expect(res.status).toBe(302)
		expect(new URL(res.headers.get('location') ?? '').hostname).toBe('idp.test')
	})
})

describe('login → callback (end to end with a fake IdP)', () => {
	test('creates a session, sets px_session, and 302s back to the original target', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, oidc: new FakeOidc({ sub: 'g-42', email: 'user@contember.com' }) })

		// 1. Login: capture the state (from the IdP URL) and the in-flight cookie.
		const login = await handleAuth(
			new Request(`${ISSUER}/auth/login?redirect=${encodeURIComponent(`${ISSUER}/back`)}`),
			services,
			AUTH_ENV,
			ctx(),
		)
		const state = new URL(login.headers.get('location') ?? '').searchParams.get('state')
		const flightCookie = setCookieValue(login, 'px_oidc')
		expect(state && flightCookie).toBeTruthy()

		// 2. Callback: the IdP bounces back with code + matching state; the in-flight cookie is replayed.
		const callback = await handleAuth(
			new Request(`${ISSUER}/auth/callback?code=abc&state=${state}`, {
				headers: { Cookie: `px_oidc=${flightCookie}` },
			}),
			services,
			AUTH_ENV,
			ctx(),
		)
		expect(callback.status).toBe(302)
		expect(callback.headers.get('location')).toBe(`${ISSUER}/back`)

		// A session cookie was issued and a session row created for the lazily-created principal.
		const sessionToken = setCookieValue(callback, SESSION_COOKIE)
		expect(sessionToken).toBeTruthy()
		const principal = await h.db.getUserByExternalId('g-42')
		expect(principal?.email).toBe('user@contember.com')
		const session = await h.db.getActiveSessionByHash(await hashToken(sessionToken ?? ''))
		expect(session?.principal_id).toBe(principal?.id)
	})

	test('a mismatched state is rejected (CSRF guard)', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, oidc: new FakeOidc({ sub: 'g', email: 'a@b.cz' }) })
		const login = await handleAuth(new Request(`${ISSUER}/auth/login`), services, AUTH_ENV, ctx())
		const flightCookie = setCookieValue(login, 'px_oidc')
		const res = await handleAuth(
			new Request(`${ISSUER}/auth/callback?code=abc&state=WRONG`, { headers: { Cookie: `px_oidc=${flightCookie}` } }),
			services,
			AUTH_ENV,
			ctx(),
		)
		expect(res.status).toBe(400)
	})

	test('a refused identity (unverified email → null) yields 401', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, oidc: new FakeOidc(null) })
		const login = await handleAuth(new Request(`${ISSUER}/auth/login`), services, AUTH_ENV, ctx())
		const flightCookie = setCookieValue(login, 'px_oidc')
		const state = new URL(login.headers.get('location') ?? '').searchParams.get('state')
		const res = await handleAuth(
			new Request(`${ISSUER}/auth/callback?code=abc&state=${state}`, { headers: { Cookie: `px_oidc=${flightCookie}` } }),
			services,
			AUTH_ENV,
			ctx(),
		)
		expect(res.status).toBe(401)
	})
})

describe('login admission (/auth/callback allowlist)', () => {
	// Drive a full login → callback for the given services + identity, returning the callback response.
	async function login(services: ReturnType<Harness['makeServices']>, identity: OidcIdentity): Promise<Response> {
		const withOidc = { ...services, oidc: new FakeOidc(identity) }
		const loginRes = await handleAuth(new Request(`${ISSUER}/auth/login`), withOidc, AUTH_ENV, ctx())
		const state = new URL(loginRes.headers.get('location') ?? '').searchParams.get('state')
		const flightCookie = setCookieValue(loginRes, 'px_oidc')
		return handleAuth(
			new Request(`${ISSUER}/auth/callback?code=abc&state=${state}`, { headers: { Cookie: `px_oidc=${flightCookie}` } }),
			withOidc,
			AUTH_ENV,
			ctx(),
		)
	}

	test('a new identity outside the allowlist is refused (403), no principal created', async () => {
		const h = createHarness()
		// Default allowlist admits only @contember.com.
		const services = h.makeServices({ issuer: ISSUER })
		const res = await login(services, { sub: 'out-1', email: 'stranger@evil.example' })
		expect(res.status).toBe(403)
		expect(await h.db.getUserByExternalId('out-1')).toBeNull()
	})

	test('a matching email domain admits a new identity (302 + session)', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER })
		const res = await login(services, { sub: 'in-1', email: 'new@contember.com' })
		expect(res.status).toBe(302)
		expect(setCookieValue(res, SESSION_COOKIE)).toBeTruthy()
	})

	test('an exact email on the allowlist admits a new identity', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, human: { emailDomains: [], emails: ['vip@evil.example'] } })
		const res = await login(services, { sub: 'vip-1', email: 'vip@evil.example' })
		expect(res.status).toBe(302)
	})

	test('a `*` wildcard admits anyone (allow-all)', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, human: { emailDomains: ['*'], emails: [] } })
		const res = await login(services, { sub: 'any-1', email: 'whoever@anywhere.example' })
		expect(res.status).toBe(302)
	})

	test('a bootstrap admin is always admitted, even outside the allowlist', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, bootstrapAdmins: new Set(['boss@evil.example']) })
		const res = await login(services, { sub: 'boss-1', email: 'boss@evil.example' })
		expect(res.status).toBe(302)
	})

	test('an already-invited principal is admitted despite an allowlist miss', async () => {
		const h = createHarness()
		// An invited row (external_id NULL) with a non-allowlisted email — claimed on first login.
		seedUser(h.sqlite, { sub: null, email: 'invited@evil.example' })
		const services = h.makeServices({ issuer: ISSUER })
		const res = await login(services, { sub: 'inv-1', email: 'invited@evil.example' })
		expect(res.status).toBe(302)
		// The invite was claimed by the IdP sub.
		expect((await h.db.getUserByExternalId('inv-1'))?.email).toBe('invited@evil.example')
	})
})

describe('GET /auth/logout', () => {
	test('revokes the session and clears the cookie', async () => {
		const h = createHarness()
		const principalId = seedUser(h.sqlite, { sub: 'g-7', email: 'l@o.cz' })
		const sessionToken = 'live-session'
		await h.db.createSession({ tokenHash: await hashToken(sessionToken), principalId, idpSub: 'g-7', expiresAt: Math.floor(Date.now() / 1000) + 3600 })

		const res = await handleAuth(
			new Request(`${ISSUER}/auth/logout`, { headers: { Cookie: `${SESSION_COOKIE}=${sessionToken}` } }),
			h.makeServices({ issuer: ISSUER }),
			AUTH_ENV,
			ctx(),
		)
		expect(res.status).toBe(302)
		// Cookie cleared (Max-Age=0) and the session no longer resolves.
		expect(res.headers.getSetCookie().some((c) => c.startsWith(`${SESSION_COOKIE}=`) && c.includes('Max-Age=0'))).toBe(true)
		expect(await h.db.getActiveSessionByHash(await hashToken(sessionToken))).toBeNull()
	})
})
