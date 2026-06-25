import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, exportJWK, generateKeyPair, type JSONWebKeySet, type JWTPayload, SignJWT } from 'jose'
import { generatePkce, GoogleOidc, randomToken } from '../oidc'

const CONFIG = {
	clientId: 'client-123.apps.googleusercontent.com',
	clientSecret: 'secret-xyz',
	redirectUri: 'https://propustka.test/auth/callback',
}

// ── A local key + JWKS so verifyIdToken runs the real jose verification without network ──
const { publicKey, privateKey } = await generateKeyPair('RS256')
const jwk = await exportJWK(publicKey)
jwk.kid = 'google-test'
jwk.alg = 'RS256'
const jwks: JSONWebKeySet = { keys: [jwk] }
const localJwks = createLocalJWKSet(jwks)

async function signIdToken(claims: JWTPayload, opts: { issuer?: string; audience?: string } = {}): Promise<string> {
	return new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', kid: 'google-test' })
		.setIssuer(opts.issuer ?? 'https://accounts.google.com')
		.setAudience(opts.audience ?? CONFIG.clientId)
		.setIssuedAt()
		.setExpirationTime('1h')
		.sign(privateKey)
}

function oidc(): GoogleOidc {
	return new GoogleOidc(CONFIG, localJwks)
}

describe('generatePkce', () => {
	test('challenge is the S256 of the verifier', async () => {
		const { verifier, challenge } = await generatePkce()
		const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
		const expected = Buffer.from(digest).toString('base64url')
		expect(challenge).toBe(expected)
	})

	test('two calls produce different verifiers', async () => {
		const a = await generatePkce()
		const b = await generatePkce()
		expect(a.verifier).not.toBe(b.verifier)
	})
})

describe('randomToken', () => {
	test('is url-safe and unique', () => {
		const t = randomToken()
		expect(t).toMatch(/^[A-Za-z0-9_-]+$/)
		expect(randomToken()).not.toBe(t)
	})
})

describe('authorizationUrl', () => {
	test('targets Google with PKCE S256 + the configured client/redirect', () => {
		const url = new URL(oidc().authorizationUrl({ state: 'st-1', codeChallenge: 'ch-1' }))
		expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth')
		expect(url.searchParams.get('client_id')).toBe(CONFIG.clientId)
		expect(url.searchParams.get('redirect_uri')).toBe(CONFIG.redirectUri)
		expect(url.searchParams.get('response_type')).toBe('code')
		expect(url.searchParams.get('scope')).toBe('openid email profile')
		expect(url.searchParams.get('state')).toBe('st-1')
		expect(url.searchParams.get('code_challenge')).toBe('ch-1')
		expect(url.searchParams.get('code_challenge_method')).toBe('S256')
	})
})

describe('tokenRequestBody', () => {
	test('carries the auth-code grant + PKCE verifier + client secret', () => {
		const body = oidc().tokenRequestBody('the-code', 'the-verifier')
		expect(body.get('grant_type')).toBe('authorization_code')
		expect(body.get('code')).toBe('the-code')
		expect(body.get('code_verifier')).toBe('the-verifier')
		expect(body.get('client_secret')).toBe(CONFIG.clientSecret)
		expect(body.get('redirect_uri')).toBe(CONFIG.redirectUri)
	})
})

describe('verifyIdToken', () => {
	test('accepts a valid, email-verified Google id_token', async () => {
		const token = await signIdToken({ sub: 'g-sub-1', email: 'a@b.cz', email_verified: true })
		expect(await oidc().verifyIdToken(token)).toEqual({ sub: 'g-sub-1', email: 'a@b.cz' })
	})

	test('accepts the string "true" form of email_verified', async () => {
		const token = await signIdToken({ sub: 'g', email: 'a@b.cz', email_verified: 'true' })
		expect(await oidc().verifyIdToken(token)).toEqual({ sub: 'g', email: 'a@b.cz' })
	})

	test('rejects an unverified email', async () => {
		const token = await signIdToken({ sub: 'g', email: 'a@b.cz', email_verified: false })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects a wrong audience (token minted for another client)', async () => {
		const token = await signIdToken({ sub: 'g', email: 'a@b.cz', email_verified: true }, { audience: 'other-client' })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects a wrong issuer', async () => {
		const token = await signIdToken({ sub: 'g', email: 'a@b.cz', email_verified: true }, { issuer: 'https://evil.example' })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects a missing email', async () => {
		const token = await signIdToken({ sub: 'g', email_verified: true })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects a garbage token', async () => {
		expect(await oidc().verifyIdToken('not.a.jwt')).toBeNull()
	})
})
