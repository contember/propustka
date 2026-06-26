/**
 * Token signing key custody for propustka-issued tokens. The Worker is now an ISSUER: it signs
 * per-app permission tokens (and capability tokens) with its own ES256 (EC P-256) key, and
 * publishes the public half so the SDK verifies locally — no per-request round-trip.
 *
 * Keys come from the `PROPUSTKA_SIGNING_KEYS` secret (a JSON array of private JWKs). Index 0 is the
 * ACTIVE signer; every key is published in the JWKS, so a freshly-added rotation key can be verified
 * (it's in the public set) before it's promoted to index 0 to sign. Locally, with no keys
 * configured, an EPHEMERAL key is generated per isolate — fine for dev (sessions reset on restart),
 * refused on stage/prod (a real deploy must provision durable keys).
 *
 * One Signer per isolate, memoised like the `JwtValidator` (jose imports the key once).
 */

import { type AccessTokenClaims, type Jwks, type PublicJwk, TOKEN_ALG } from '@propustka/core'
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK, type KeyLike, SignJWT } from 'jose'
import type { Env } from './env'
import { stringField } from './json'

/** A key jose can sign with (a CryptoKey-like `KeyLike` or a raw secret). */
type SignKey = KeyLike | Uint8Array

interface LoadedKey {
	kid: string
	/** Private key material, for signing. */
	key: SignKey
	/** Public half, for the JWKS. */
	publicJwk: PublicJwk
}

export class Signer {
	private constructor(private readonly keys: LoadedKey[]) {}

	/**
	 * Sign a claims object with the ACTIVE key. The `kid` goes in the protected header so the SDK
	 * picks the matching public JWK. The claims already carry `iss`/`aud`/`exp` (built in core).
	 */
	sign(claims: AccessTokenClaims): Promise<string> {
		const active = this.keys[0]
		if (!active) {
			throw new Error('Signer has no keys')
		}
		return new SignJWT({ ...claims })
			.setProtectedHeader({ alg: TOKEN_ALG, kid: active.kid })
			.sign(active.key)
	}

	/** The public key set — active key first, then any rotation keys. */
	jwks(): Jwks {
		return { keys: this.keys.map((k) => k.publicJwk) }
	}

	/** Import the configured private JWKs (index 0 = active signer). */
	static async fromPrivateJwks(jwks: JWK[]): Promise<Signer> {
		const keys: LoadedKey[] = []
		for (const jwk of jwks) {
			const key = await importJWK(jwk, TOKEN_ALG)
			const kid = jwk.kid ?? (await calculateJwkThumbprint(jwk))
			keys.push({ kid, key, publicJwk: toPublicJwk(jwk, kid) })
		}
		if (keys.length === 0) {
			throw new Error('No signing keys configured')
		}
		return new Signer(keys)
	}

	/** Generate an ephemeral signer — LOCAL DEV ONLY (rotates on isolate restart; sessions reset). */
	static async ephemeral(): Promise<Signer> {
		const { publicKey, privateKey } = await generateKeyPair(TOKEN_ALG, { extractable: true })
		const publicJwk = await exportJWK(publicKey)
		const kid = await calculateJwkThumbprint(publicJwk)
		return new Signer([{ kid, key: privateKey, publicJwk: toPublicJwk(publicJwk, kid) }])
	}
}

/** Pick the public members of a JWK (drop the private `d`); stamp our alg/use/kid. */
function toPublicJwk(jwk: JWK, kid: string): PublicJwk {
	return {
		kty: jwk.kty ?? 'EC',
		crv: jwk.crv,
		x: jwk.x,
		y: jwk.y,
		kid,
		alg: TOKEN_ALG,
		use: 'sig',
	}
}

/** Parse `PROPUSTKA_SIGNING_KEYS` into private JWKs. Throws loudly on malformed config (fail the deploy). */
export function parseSigningKeys(raw: string): JWK[] {
	if (raw.trim() === '') {
		return []
	}
	let parsed: unknown
	try {
		parsed = JSON.parse(raw)
	} catch {
		throw new Error('PROPUSTKA_SIGNING_KEYS is not valid JSON')
	}
	if (!Array.isArray(parsed)) {
		throw new Error('PROPUSTKA_SIGNING_KEYS must be a JSON array of private JWKs')
	}
	return parsed.map((item, index) => parseEcPrivateJwk(item, index))
}

/** Build a typed EC P-256 private JWK from an untrusted object (no `as`); reject anything else. */
function parseEcPrivateJwk(value: unknown, index: number): JWK {
	const kty = stringField(value, 'kty')
	const crv = stringField(value, 'crv')
	const x = stringField(value, 'x')
	const y = stringField(value, 'y')
	const d = stringField(value, 'd')
	const kid = stringField(value, 'kid')
	if (kty !== 'EC' || crv !== 'P-256' || x === undefined || y === undefined || d === undefined) {
		throw new Error(`PROPUSTKA_SIGNING_KEYS[${index}] must be an EC P-256 private JWK (kty=EC, crv=P-256, x, y, d)`)
	}
	return { kty, crv, x, y, d, alg: TOKEN_ALG, use: 'sig', ...(kid === undefined ? {} : { kid }) }
}

// ── Per-isolate memoisation ────────────────────────────────────────────────────

let cached: { key: string; signer: Promise<Signer> } | undefined

/** The isolate-cached Signer for this env. Returns a promise (key import is async). */
export function getSigner(env: Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>): Promise<Signer> {
	const raw = env.PROPUSTKA_SIGNING_KEYS ?? ''
	const cacheKey = `${env.ENVIRONMENT}::${raw}`
	if (cached && cached.key === cacheKey) {
		return cached.signer
	}
	const signer = buildSigner(env.ENVIRONMENT, raw).catch((err: unknown) => {
		// Don't cache a rejected promise — a fixed config should be retried, not poisoned.
		if (cached?.key === cacheKey) {
			cached = undefined
		}
		throw err
	})
	cached = { key: cacheKey, signer }
	return signer
}

async function buildSigner(environment: string, raw: string): Promise<Signer> {
	const jwks = parseSigningKeys(raw)
	if (jwks.length > 0) {
		return Signer.fromPrivateJwks(jwks)
	}
	if (environment === 'local') {
		return Signer.ephemeral()
	}
	throw new Error('PROPUSTKA_SIGNING_KEYS is empty — provide an ES256 private JWK array for stage/prod.')
}
