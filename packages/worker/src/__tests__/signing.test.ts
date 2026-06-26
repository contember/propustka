import { buildAccessClaims, parseAccessClaims, type PermissionEntry, TOKEN_ALG } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify } from 'jose'
import { parseSigningKeys, Signer } from '../signing'

const ISS = 'https://propustka.test'
const perms: PermissionEntry[] = [{ action: 'project.read', scope: { type: 'project', value: 'demo' }, source: 'grant' }]

/** Generate a real ES256 keypair and return its PRIVATE jwk (with `d`), as the secret would hold. */
async function privateJwk(kid?: string) {
	const { privateKey } = await generateKeyPair(TOKEN_ALG, { extractable: true })
	const jwk = await exportJWK(privateKey)
	if (kid !== undefined) {
		jwk.kid = kid
	}
	return jwk
}

function principalClaims() {
	return buildAccessClaims({
		iss: ISS,
		app: 'example-app',
		subject: 'user-1',
		type: 'user',
		label: 'a@b.cz',
		permissions: perms,
		issuedAt: Math.floor(Date.now() / 1000),
		expiresAt: Math.floor(Date.now() / 1000) + 300,
	})
}

describe('Signer.fromPrivateJwks', () => {
	test('signs a token the published JWKS verifies, round-tripping the claims', async () => {
		const jwk = await privateJwk('key-1')
		const signer = await Signer.fromPrivateJwks([jwk])

		const token = await signer.sign(principalClaims())

		// Verify EXACTLY as the SDK will: a local JWKS built from signer.jwks(), checking iss + aud.
		const localJwks = createLocalJWKSet(signer.jwks())
		const { payload } = await jwtVerify(token, localJwks, { issuer: ISS, audience: 'example-app' })

		const claims = parseAccessClaims(payload)
		expect(claims?.ptype).toBe('user')
		expect(claims?.perms).toEqual(perms)
	})

	test('jwks() publishes the public half only (no private `d`) and carries the kid', async () => {
		const signer = await Signer.fromPrivateJwks([await privateJwk('key-1')])
		const jwks = signer.jwks()
		expect(jwks.keys).toHaveLength(1)
		const [key] = jwks.keys
		expect(key?.kid).toBe('key-1')
		expect(key?.use).toBe('sig')
		expect(key && 'd' in key).toBe(false)
	})

	test('signs with the ACTIVE (index 0) key but publishes all for rotation', async () => {
		const active = await privateJwk('active')
		const next = await privateJwk('next')
		const signer = await Signer.fromPrivateJwks([active, next])

		expect(signer.jwks().keys.map((k) => k.kid)).toEqual(['active', 'next'])

		// A token verifies against the multi-key set, and its header kid is the active one.
		const token = await signer.sign(principalClaims())
		const [headerB64] = token.split('.')
		const header: unknown = JSON.parse(Buffer.from(headerB64 ?? '', 'base64url').toString())
		expect(header && typeof header === 'object' && 'kid' in header && header.kid).toBe('active')
		await jwtVerify(token, createLocalJWKSet(signer.jwks()), { issuer: ISS, audience: 'example-app' })
	})

	test('a kid is derived from the JWK thumbprint when absent', async () => {
		const signer = await Signer.fromPrivateJwks([await privateJwk()])
		expect(signer.jwks().keys[0]?.kid).toBeTruthy()
	})
})

describe('Signer.ephemeral', () => {
	test('mints a verifiable token without configured keys (local dev)', async () => {
		const signer = await Signer.ephemeral()
		const token = await signer.sign(principalClaims())
		const { payload } = await jwtVerify(token, createLocalJWKSet(signer.jwks()), { issuer: ISS, audience: 'example-app' })
		expect(parseAccessClaims(payload)?.sub).toBe('user-1')
	})
})

describe('parseSigningKeys', () => {
	test('empty string → no keys', () => {
		expect(parseSigningKeys('')).toEqual([])
		expect(parseSigningKeys('   ')).toEqual([])
	})

	test('parses a valid EC P-256 private JWK array', async () => {
		const jwk = await privateJwk('key-1')
		const parsed = parseSigningKeys(JSON.stringify([jwk]))
		expect(parsed).toHaveLength(1)
		expect(parsed[0]?.kid).toBe('key-1')
	})

	test('throws on non-JSON', () => {
		expect(() => parseSigningKeys('{not json')).toThrow(/not valid JSON/)
	})

	test('throws on a non-array', () => {
		expect(() => parseSigningKeys('{"kty":"EC"}')).toThrow(/must be a JSON array/)
	})

	test('throws on a non-EC / incomplete key', () => {
		expect(() => parseSigningKeys('[{"kty":"RSA","n":"x","e":"AQAB","d":"y"}]')).toThrow(/EC P-256 private JWK/)
		expect(() => parseSigningKeys('[{"kty":"EC","crv":"P-256","x":"a","y":"b"}]')).toThrow(/EC P-256 private JWK/)
	})
})
