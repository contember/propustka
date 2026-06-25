import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, exportJWK, generateKeyPair, type JSONWebKeySet, type JWTPayload, SignJWT } from 'jose'
import { generatePkce, OidcClient, type OidcConfig, type OidcMetadata, randomToken } from '../oidc'

const ISSUER = 'https://idp.test'
const METADATA: OidcMetadata = {
	issuer: ISSUER,
	authorizationEndpoint: 'https://idp.test/authorize',
	tokenEndpoint: 'https://idp.test/token',
	jwksUri: 'https://idp.test/jwks',
}
const CONFIG: OidcConfig = {
	issuer: ISSUER,
	clientId: 'client-123',
	clientSecret: 'secret-xyz',
	redirectUri: 'https://propustka.test/auth/callback',
	scopes: '',
	requireVerifiedEmail: true,
}

// A local key + JWKS so verifyIdToken runs the real jose verification without network.
const { publicKey, privateKey } = await generateKeyPair('RS256')
const jwk = await exportJWK(publicKey)
jwk.kid = 'idp-test'
jwk.alg = 'RS256'
const jwks: JSONWebKeySet = { keys: [jwk] }
const localJwks = createLocalJWKSet(jwks)

async function signIdToken(claims: JWTPayload, opts: { issuer?: string; audience?: string } = {}): Promise<string> {
	return new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', kid: 'idp-test' })
		.setIssuer(opts.issuer ?? ISSUER)
		.setAudience(opts.audience ?? CONFIG.clientId)
		.setIssuedAt()
		.setExpirationTime('1h')
		.sign(privateKey)
}

/** A client with discovery + JWKS injected (no network). */
function oidc(overrides: Partial<OidcConfig> = {}): OidcClient {
	return new OidcClient({ ...CONFIG, ...overrides }, { metadata: METADATA, jwks: localJwks })
}

describe('generatePkce', () => {
	test('challenge is the S256 of the verifier', async () => {
		const { verifier, challenge } = await generatePkce()
		const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
		expect(challenge).toBe(Buffer.from(digest).toString('base64url'))
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
	test('targets the DISCOVERED authorization endpoint with PKCE + configured client/redirect', async () => {
		const url = new URL(await oidc().authorizationUrl({ state: 'st-1', codeChallenge: 'ch-1' }))
		expect(url.origin + url.pathname).toBe('https://idp.test/authorize')
		expect(url.searchParams.get('client_id')).toBe(CONFIG.clientId)
		expect(url.searchParams.get('redirect_uri')).toBe(CONFIG.redirectUri)
		expect(url.searchParams.get('scope')).toBe('openid email profile') // default
		expect(url.searchParams.get('state')).toBe('st-1')
		expect(url.searchParams.get('code_challenge')).toBe('ch-1')
		expect(url.searchParams.get('code_challenge_method')).toBe('S256')
	})

	test('honors custom scopes', async () => {
		const url = new URL(await oidc({ scopes: 'openid email groups' }).authorizationUrl({ state: 's', codeChallenge: 'c' }))
		expect(url.searchParams.get('scope')).toBe('openid email groups')
	})
})

describe('tokenRequestBody', () => {
	test('carries the auth-code grant + PKCE verifier + client secret', () => {
		const body = oidc().tokenRequestBody('the-code', 'the-verifier')
		expect(body.get('grant_type')).toBe('authorization_code')
		expect(body.get('code')).toBe('the-code')
		expect(body.get('code_verifier')).toBe('the-verifier')
		expect(body.get('client_secret')).toBe(CONFIG.clientSecret)
	})
})

describe('verifyIdToken', () => {
	test('accepts a valid, email-verified token', async () => {
		const token = await signIdToken({ sub: 's-1', email: 'a@b.cz', email_verified: true })
		expect(await oidc().verifyIdToken(token)).toEqual({ sub: 's-1', email: 'a@b.cz' })
	})

	test('accepts the string "true" form of email_verified', async () => {
		const token = await signIdToken({ sub: 's', email: 'a@b.cz', email_verified: 'true' })
		expect(await oidc().verifyIdToken(token)).toEqual({ sub: 's', email: 'a@b.cz' })
	})

	test('rejects an unverified email when verification is required', async () => {
		const token = await signIdToken({ sub: 's', email: 'a@b.cz', email_verified: false })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('with requireVerifiedEmail=false, a MISSING claim is accepted but an explicit false is still rejected', async () => {
		const lenient = oidc({ requireVerifiedEmail: false })
		const missing = await signIdToken({ sub: 's', email: 'a@b.cz' })
		expect(await lenient.verifyIdToken(missing)).toEqual({ sub: 's', email: 'a@b.cz' })
		const explicitFalse = await signIdToken({ sub: 's', email: 'a@b.cz', email_verified: false })
		expect(await lenient.verifyIdToken(explicitFalse)).toBeNull()
	})

	test('rejects a wrong audience', async () => {
		const token = await signIdToken({ sub: 's', email: 'a@b.cz', email_verified: true }, { audience: 'other' })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects a wrong issuer (must match the discovered issuer)', async () => {
		const token = await signIdToken({ sub: 's', email: 'a@b.cz', email_verified: true }, { issuer: 'https://evil.example' })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects a missing email', async () => {
		const token = await signIdToken({ sub: 's', email_verified: true })
		expect(await oidc().verifyIdToken(token)).toBeNull()
	})

	test('rejects garbage', async () => {
		expect(await oidc().verifyIdToken('not.a.jwt')).toBeNull()
	})
})

describe('discovery', () => {
	test('returns the injected metadata without a network call', async () => {
		expect(await oidc().metadata()).toEqual(METADATA)
	})
})
