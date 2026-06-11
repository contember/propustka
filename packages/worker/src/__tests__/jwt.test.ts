import { describe, expect, test } from 'bun:test'
import { createLocalJWKSet, exportJWK, generateKeyPair, type JSONWebKeySet, type JWTPayload, type KeyLike, SignJWT } from 'jose'
import { type AccessApps, JwtValidator } from '../jwt'

// FINDING TEST-3: JwtValidator.validate is core security logic and was entirely
// untested. These tests stand up a real local RSA key pair + JWKS (mirroring how
// schema.test.ts spins up a real in-memory dependency) and drive validate() end to
// end: jose performs the genuine signature/issuer/audience verification, and we
// then assert on the aud→app resolution and the user/service discrimination that
// ground the "verified app id" and principal-identity model.

const TEAM = 'https://team.cloudflareaccess.com'
const ALG = 'RS256'

// ACCESS_APPS: { aud tag → configured app id }. Two configured tags so we can prove
// resolveApp intersects a multi-value aud with the configured set rather than just
// reading aud[0].
const ACCESS_APPS: AccessApps = {
	'aud-admin-tag': 'admin',
	'aud-portal-tag': 'portal',
}
const UNKNOWN_AUD = 'aud-unconfigured-tag'

// One shared key pair + JWKS for the whole suite. The validator is given a
// createLocalJWKSet resolver bound to the public key, so jwtVerify resolves the
// signing key locally (no network) while still doing the real cryptographic check.
const { publicKey, privateKey } = await generateKeyPair(ALG)
const jwk = await exportJWK(publicKey)
jwk.kid = 'test-key-1'
jwk.alg = ALG
jwk.use = 'sig'
const jwks: JSONWebKeySet = { keys: [jwk] }

function validatorWithLocalKeys(accessApps: AccessApps = ACCESS_APPS): JwtValidator {
	return new JwtValidator(TEAM, accessApps, createLocalJWKSet(jwks))
}

interface SignOptions {
	issuer?: string
	audience?: string | string[]
	/** Skip setting exp (defaults to a future value otherwise). */
	expiresIn?: string
	/** Set exp to a past instant. */
	expired?: boolean
	/** Sign with a different, untrusted key. */
	wrongKey?: KeyLike
}

async function sign(claims: JWTPayload, opts: SignOptions = {}): Promise<string> {
	let jwt = new SignJWT(claims)
		.setProtectedHeader({ alg: ALG, kid: 'test-key-1' })
		.setIssuer(opts.issuer ?? TEAM)
		.setIssuedAt()
		.setAudience(opts.audience ?? 'aud-admin-tag')

	if (opts.expired) {
		jwt = jwt.setExpirationTime(Math.floor(Date.now() / 1000) - 60)
	} else {
		jwt = jwt.setExpirationTime(opts.expiresIn ?? '1h')
	}
	return jwt.sign(opts.wrongKey ?? privateKey)
}

describe('JwtValidator.validate — happy paths', () => {
	test('valid user token (email + sub) → ok, kind user, verified app from aud', async () => {
		const token = await sign({ email: 'alice@example.com', sub: 'sub-alice' }, { audience: 'aud-admin-tag' })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.kind).toBe('user')
		// The app id is the *configured* value, not the raw aud tag.
		expect(result.app).toBe('admin')
		if (result.kind !== 'user') throw new Error('expected user kind')
		expect(result.email).toBe('alice@example.com')
		expect(result.sub).toBe('sub-alice')
	})

	test('valid service token (common_name, no email/sub) → ok, kind service', async () => {
		const token = await sign({ common_name: 'svc-client-id-123' }, { audience: 'aud-portal-tag' })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.kind).toBe('service')
		expect(result.app).toBe('portal')
		if (result.kind !== 'service') throw new Error('expected service kind')
		expect(result.commonName).toBe('svc-client-id-123')
	})

	test('a token carrying BOTH email/sub and common_name resolves as user (identity wins)', async () => {
		const token = await sign(
			{ email: 'alice@example.com', sub: 'sub-alice', common_name: 'svc-client' },
			{ audience: 'aud-admin-tag' },
		)
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.kind).toBe('user')
	})
})

describe('JwtValidator.validate — resolveApp over the aud set', () => {
	test('aud as an array containing one configured tag resolves to that app', async () => {
		const token = await sign(
			{ email: 'bob@example.com', sub: 'sub-bob' },
			{ audience: [UNKNOWN_AUD, 'aud-portal-tag'] },
		)
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.app).toBe('portal')
	})

	test('aud array picks the FIRST configured tag when several are present', async () => {
		// resolveApp iterates aud in order and returns the first configured match.
		const token = await sign(
			{ email: 'carol@example.com', sub: 'sub-carol' },
			{ audience: ['aud-admin-tag', 'aud-portal-tag'] },
		)
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.app).toBe('admin')
	})

	test('aud carrying ONLY an unconfigured tag is rejected (jose audience check) as invalid_token', async () => {
		// The validator passes Object.keys(accessApps) as jose's audience set, so a
		// token whose aud is disjoint from the configured tags is rejected by jose
		// up front — surfacing invalid_token, never reaching resolveApp. This is the
		// outer guard that makes the resolveApp `aud_not_configured` branch defensive.
		const token = await sign({ email: 'dan@example.com', sub: 'sub-dan' }, { audience: UNKNOWN_AUD })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
		expect(result.logReason).toBe('invalid_token')
	})

	test('aud_not_configured (defensive branch): aud array carries a configured tag for jose plus an extra unknown one — resolves to the configured app', async () => {
		// jwt.ts:92-98 is documented as a defensive branch: because jose is given
		// Object.keys(accessApps) as its audience set, any aud that passes jose MUST
		// contain at least one configured tag, which resolveApp then finds. We prove
		// that coupling here — an aud carrying a configured tag AND an unknown one
		// verifies and resolves to the configured app (rather than the unknown tag
		// shadowing it), so resolveApp never returns undefined for a jose-accepted
		// token. The `aud_not_configured` log reason is thus unreachable in practice
		// short of a jose/accessApps divergence, exactly as the source comment notes.
		const token = await sign(
			{ email: 'erin@example.com', sub: 'sub-erin' },
			{ audience: ['aud-portal-tag', UNKNOWN_AUD] },
		)
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(true)
		if (!result.ok) throw new Error('expected ok')
		expect(result.app).toBe('portal')
	})
})

describe('JwtValidator.validate — identity-claim failures', () => {
	test('verified token missing every identity claim → no_identity_claim', async () => {
		const token = await sign({ scope: 'whatever' }, { audience: 'aud-admin-tag' })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
		expect(result.logReason).toBe('no_identity_claim')
	})

	test('email present but sub empty → no_identity_claim (not treated as a user)', async () => {
		const token = await sign({ email: 'frank@example.com', sub: '' }, { audience: 'aud-admin-tag' })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.logReason).toBe('no_identity_claim')
	})

	test('email present but sub missing → no_identity_claim', async () => {
		const token = await sign({ email: 'grace@example.com' }, { audience: 'aud-admin-tag' })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.logReason).toBe('no_identity_claim')
	})
})

describe('JwtValidator.validate — token rejection (jose)', () => {
	test('null token → missing_token', async () => {
		const result = await validatorWithLocalKeys().validate(null)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('missing_token')
		expect(result.logReason).toBe('missing_token')
	})

	test('garbage / unparseable token → invalid_token', async () => {
		const result = await validatorWithLocalKeys().validate('not-a-jwt')

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
		expect(result.logReason).toBe('invalid_token')
	})

	test('wrong-signature token → invalid_token', async () => {
		const other = await generateKeyPair(ALG)
		const token = await sign(
			{ email: 'mallory@example.com', sub: 'sub-mallory' },
			{ audience: 'aud-admin-tag', wrongKey: other.privateKey },
		)
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
	})

	test('expired token → invalid_token', async () => {
		const token = await sign({ email: 'oscar@example.com', sub: 'sub-oscar' }, { audience: 'aud-admin-tag', expired: true })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
	})

	test('wrong issuer → invalid_token', async () => {
		const token = await sign(
			{ email: 'peggy@example.com', sub: 'sub-peggy' },
			{ audience: 'aud-admin-tag', issuer: 'https://attacker.example.com' },
		)
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
	})

	test('audience not in the configured set → invalid_token', async () => {
		const token = await sign({ email: 'trent@example.com', sub: 'sub-trent' }, { audience: UNKNOWN_AUD })
		const result = await validatorWithLocalKeys().validate(token)

		expect(result.ok).toBe(false)
		if (result.ok) throw new Error('expected failure')
		expect(result.reason).toBe('invalid_token')
	})
})
