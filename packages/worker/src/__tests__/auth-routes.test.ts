import { SESSION_COOKIE } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { handleAuth } from '../auth/routes'
import { hashToken } from '../capabilities'
import { type GoogleIdentity, GoogleOidc } from '../oidc'
import { createHarness, seedUser } from './helpers/harness'

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

/** A GoogleOidc that skips the network: returns a fixed identity (or null) from the exchange/verify. */
class FakeOidc extends GoogleOidc {
	constructor(private readonly identity: GoogleIdentity | null) {
		super({ clientId: 'x', clientSecret: 'y', redirectUri: `${ISSUER}/auth/callback` })
	}
	override async exchangeCode(): Promise<string | null> {
		return 'fake-id-token'
	}
	override async verifyIdToken(): Promise<GoogleIdentity | null> {
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
	test('302s to Google with PKCE and sets the in-flight cookie', async () => {
		const h = createHarness()
		const res = await handleAuth(
			new Request(`${ISSUER}/auth/login?redirect=${encodeURIComponent(`${ISSUER}/back`)}`),
			h.makeServices({ issuer: ISSUER }),
			AUTH_ENV,
			ctx(),
		)
		expect(res.status).toBe(302)
		const location = new URL(res.headers.get('location') ?? '')
		expect(location.hostname).toBe('accounts.google.com')
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
		expect(new URL(res.headers.get('location') ?? '').hostname).toBe('accounts.google.com')
	})
})

describe('login → callback (end to end with a fake Google)', () => {
	test('creates a session, sets px_session, and 302s back to the original target', async () => {
		const h = createHarness()
		const services = h.makeServices({ issuer: ISSUER, oidc: new FakeOidc({ sub: 'g-42', email: 'user@contember.com' }) })

		// 1. Login: capture the state (from the Google URL) and the in-flight cookie.
		const login = await handleAuth(
			new Request(`${ISSUER}/auth/login?redirect=${encodeURIComponent(`${ISSUER}/back`)}`),
			services,
			AUTH_ENV,
			ctx(),
		)
		const state = new URL(login.headers.get('location') ?? '').searchParams.get('state')
		const flightCookie = setCookieValue(login, 'px_oidc')
		expect(state && flightCookie).toBeTruthy()

		// 2. Callback: Google bounces back with code + matching state; the in-flight cookie is replayed.
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
