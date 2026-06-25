/**
 * The propustka-native auth HTTP surface (public — NOT behind the admin Access gate):
 *
 *   GET  /.well-known/jwks.json  — the public signing keys (so anything can verify a token)
 *   GET  /auth/login?redirect=…  — start Google OIDC (PKCE), 302 to Google
 *   GET  /auth/callback          — finish OIDC, create the SSO session, set the cookie, 302 back
 *   GET|POST /auth/logout        — revoke the session + clear the cookie
 *
 * NOTE (migration): while propustka's own hostname is still fronted by Cloudflare Access, these
 * paths need an Access BYPASS carve-out (a `public` rule in propustka.access.ts) so the browser
 * and the app-side SDK reach them without an Access login. Once Access is gone they're plain public.
 */

import { SESSION_COOKIE } from '@propustka/core'
import { hashToken } from '../capabilities'
import type { Env } from '../env'
import { resolveUserPrincipal } from '../resolve'
import type { Config, Services } from '../services'
import { getSigner } from '../signing'
import { generatePkce, randomToken } from '../oidc'
import { clearCookie, readCookie, serializeCookie } from './cookies'

/** SSO session lifetime — the long-lived credential a browser carries (30 days). */
const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60
/** In-flight OIDC cookie (state + PKCE verifier + redirect target); short-lived, host-only on /auth. */
const OIDC_COOKIE = 'px_oidc'
const OIDC_TTL_SECONDS = 600

/** The only env the auth surface touches directly is the signing config (for the JWKS endpoint). */
type AuthEnv = Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>

export async function handleAuth(request: Request, services: Services, env: AuthEnv, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url)
	const secure = url.protocol === 'https:'

	if (url.pathname === '/.well-known/jwks.json') {
		return handleJwks(env)
	}
	if (url.pathname === '/auth/login') {
		return handleLogin(request, services, secure)
	}
	if (url.pathname === '/auth/callback') {
		return handleCallback(request, services, secure, ctx)
	}
	if (url.pathname === '/auth/logout') {
		return handleLogout(request, services, secure)
	}
	return new Response('Not found', { status: 404 })
}

// ── /.well-known/jwks.json ─────────────────────────────────────────────────────

async function handleJwks(env: AuthEnv): Promise<Response> {
	const signer = await getSigner(env)
	return Response.json(signer.jwks(), {
		headers: { 'cache-control': 'public, max-age=3600', 'access-control-allow-origin': '*' },
	})
}

// ── /auth/login ────────────────────────────────────────────────────────────────

async function handleLogin(request: Request, services: Services, secure: boolean): Promise<Response> {
	const url = new URL(request.url)
	const redirect = safeRedirect(url.searchParams.get('redirect'), services.config)

	const { verifier, challenge } = await generatePkce()
	const state = randomToken(16)
	const location = services.oidc.authorizationUrl({ state, codeChallenge: challenge })

	const flight = encodeFlight({ state, verifier, redirect })
	const headers = new Headers({ location })
	// The in-flight cookie is scoped to /auth (only the callback reads it) and is single-use.
	headers.append(
		'Set-Cookie',
		serializeCookie(OIDC_COOKIE, flight, { httpOnly: true, secure, sameSite: 'Lax', maxAge: OIDC_TTL_SECONDS, path: '/auth' }),
	)
	return new Response(null, { status: 302, headers })
}

// ── /auth/callback ───────────────────────────────────────────────────────────────

async function handleCallback(request: Request, services: Services, secure: boolean, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url)
	const code = url.searchParams.get('code')
	const state = url.searchParams.get('state')
	const flight = decodeFlight(readCookie(request.headers.get('Cookie'), OIDC_COOKIE))

	// CSRF: the state echoed by Google must match the one we stored in the in-flight cookie.
	if (!code || !state || !flight || flight.state !== state) {
		return authError('invalid OIDC state', 400)
	}

	const idToken = await services.oidc.exchangeCode(code, flight.verifier)
	if (!idToken) {
		return authError('code exchange failed', 502)
	}
	const identity = await services.oidc.verifyIdToken(idToken)
	if (!identity) {
		return authError('invalid id_token', 401)
	}

	// Resolve (or claim/lazy-create) the principal from the verified Google identity — the same
	// 3-step flow the legacy Access path uses, keyed on the IdP `sub` and verified email.
	const resolved = await resolveUserPrincipal(services.db, identity.sub, identity.email)
	if (!resolved.ok) {
		return authError(`login refused (${resolved.reason})`, 403)
	}

	// Mint the SSO session: store only the hash, hand the browser the plaintext in a cookie.
	const sessionToken = randomToken(32)
	const expiresAt = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS
	await services.db.createSession({
		tokenHash: await hashToken(sessionToken),
		principalId: resolved.principal.id,
		idpSub: identity.sub,
		email: identity.email,
		expiresAt,
	})
	ctx.waitUntil(
		services.db.writeAuthLog({
			requestId: request.headers.get('cf-ray') ?? crypto.randomUUID(),
			app: 'propustka',
			kind: 'authenticate',
			principalId: resolved.principal.id,
			decision: 'allow',
			reason: 'login',
		}),
	)

	const headers = new Headers({ location: safeRedirect(flight.redirect, services.config) })
	headers.append('Set-Cookie', sessionCookie(sessionToken, services.config, secure))
	headers.append('Set-Cookie', clearCookie(OIDC_COOKIE, { path: '/auth', secure }))
	return new Response(null, { status: 302, headers })
}

// ── /auth/logout ─────────────────────────────────────────────────────────────────

async function handleLogout(request: Request, services: Services, secure: boolean): Promise<Response> {
	const cookie = readCookie(request.headers.get('Cookie'), SESSION_COOKIE)
	if (cookie) {
		await services.db.revokeSessionByHash(await hashToken(cookie))
	}
	const url = new URL(request.url)
	const headers = new Headers({ location: safeRedirect(url.searchParams.get('redirect'), services.config) })
	headers.append(
		'Set-Cookie',
		clearCookie(SESSION_COOKIE, { path: '/', secure, ...(services.config.sessionCookieDomain ? { domain: services.config.sessionCookieDomain } : {}) }),
	)
	return new Response(null, { status: 302, headers })
}

// ── Helpers ──────────────────────────────────────────────────────────────────────

/** Build the long-lived SSO session `Set-Cookie` (parent-domain when configured). */
function sessionCookie(value: string, config: Config, secure: boolean): string {
	return serializeCookie(SESSION_COOKIE, value, {
		httpOnly: true,
		secure,
		sameSite: 'Lax',
		maxAge: SESSION_TTL_SECONDS,
		path: '/',
		...(config.sessionCookieDomain ? { domain: config.sessionCookieDomain } : {}),
	})
}

/** The in-flight OIDC state carried between /auth/login and /auth/callback. */
interface Flight {
	state: string
	verifier: string
	redirect: string
}

function encodeFlight(flight: Flight): string {
	return btoa(JSON.stringify(flight)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '')
}

function decodeFlight(raw: string | null): Flight | null {
	if (!raw) {
		return null
	}
	try {
		const json: unknown = JSON.parse(atob(raw.replaceAll('-', '+').replaceAll('_', '/')))
		const state = typeof json === 'object' && json !== null && 'state' in json ? json.state : undefined
		const verifier = typeof json === 'object' && json !== null && 'verifier' in json ? json.verifier : undefined
		const redirect = typeof json === 'object' && json !== null && 'redirect' in json ? json.redirect : undefined
		if (typeof state !== 'string' || typeof verifier !== 'string' || typeof redirect !== 'string') {
			return null
		}
		return { state, verifier, redirect }
	} catch {
		return null
	}
}

/**
 * Open-redirect guard. Accept only an absolute URL whose host is propustka's own, within the
 * configured session-cookie domain, or localhost (dev); anything else falls back to the issuer
 * origin. Prevents `/auth/login?redirect=https://evil.example` from bouncing a logged-in user out.
 */
export function safeRedirect(raw: string | null, config: Config): string {
	if (!raw) {
		return config.issuer
	}
	let target: URL
	try {
		target = new URL(raw)
	} catch {
		return config.issuer
	}
	const issuerHost = safeHost(config.issuer)
	const host = target.hostname
	const isLocal = host === 'localhost' || host === '127.0.0.1'
	const httpsOk = target.protocol === 'https:' || (target.protocol === 'http:' && isLocal)
	const domain = config.sessionCookieDomain.replace(/^\./, '')
	const hostOk = host === issuerHost || isLocal || (domain !== '' && (host === domain || host.endsWith(`.${domain}`)))
	return httpsOk && hostOk ? target.toString() : config.issuer
}

function safeHost(origin: string): string {
	try {
		return new URL(origin).hostname
	} catch {
		return ''
	}
}

/** A minimal error page for the browser-facing auth flow (the happy path always redirects). */
function authError(message: string, status: number): Response {
	return new Response(`Authentication error: ${message}`, {
		status,
		headers: { 'content-type': 'text/plain; charset=utf-8' },
	})
}
