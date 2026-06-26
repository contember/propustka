import { describe, expect, test } from 'bun:test'
import { generateToken, hashToken } from '../secret'

describe('hashToken', () => {
	test('is deterministic SHA-256 hex (64 chars)', async () => {
		const a = await hashToken('secret')
		const b = await hashToken('secret')
		expect(a).toBe(b)
		expect(a).toMatch(/^[0-9a-f]{64}$/)
	})

	test('different tokens hash differently', async () => {
		expect(await hashToken('a')).not.toBe(await hashToken('b'))
	})
})

describe('generateToken', () => {
	test('produces a high-entropy url-safe token', () => {
		const t = generateToken()
		expect(t).toMatch(/^[A-Za-z0-9_-]+$/)
		// 20 random bytes → 27 base64url chars; comfortably over the 128-bit minimum.
		expect(t.length).toBeGreaterThanOrEqual(27)
	})

	test('two tokens differ', () => {
		expect(generateToken()).not.toBe(generateToken())
	})
})
