import type { IssueCapabilityGrant, PermissionEntry } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { classifyRedeemFailure, findUncoveredGrant, generateToken, hashToken } from '../capabilities'
import type { CapabilityTokenRow } from '../db'

const NOW = 1_000_000 // unix seconds

const tokenRow = (overrides: Partial<CapabilityTokenRow>): CapabilityTokenRow => ({
	id: 't1',
	token_hash: 'hash',
	label: null,
	issued_by: 'p1',
	expires_at: null,
	max_uses: null,
	used_count: 0,
	revoked_at: null,
	created_at: NOW - 100,
	...overrides,
})

describe('classifyRedeemFailure', () => {
	test('no row → unknown', () => {
		expect(classifyRedeemFailure(null, NOW)).toBe('unknown')
	})

	test('revoked token → revoked', () => {
		expect(classifyRedeemFailure(tokenRow({ revoked_at: NOW - 10 }), NOW)).toBe('revoked')
	})

	test('expired token → expired', () => {
		expect(classifyRedeemFailure(tokenRow({ expires_at: NOW - 1 }), NOW)).toBe('expired')
	})

	test('expiry exactly now → expired (boundary is inclusive)', () => {
		expect(classifyRedeemFailure(tokenRow({ expires_at: NOW }), NOW)).toBe('expired')
	})

	test('exhausted token → exhausted', () => {
		expect(classifyRedeemFailure(tokenRow({ max_uses: 3, used_count: 3 }), NOW)).toBe('exhausted')
	})

	test('revoked outranks expired', () => {
		expect(classifyRedeemFailure(tokenRow({ revoked_at: NOW - 5, expires_at: NOW - 1 }), NOW)).toBe('revoked')
	})

	test('still-valid row (race) → unknown (fail closed)', () => {
		expect(classifyRedeemFailure(tokenRow({}), NOW)).toBe('unknown')
	})
})

const entry = (action: string, projectId: string | null): PermissionEntry => ({ action, projectId, source: 'grant' })

describe('findUncoveredGrant (delegation rule)', () => {
	const grant = (action: string, projectId?: string | null): IssueCapabilityGrant => ({
		action,
		resource: 'report:1',
		...(projectId !== undefined ? { projectId } : {}),
	})

	test('all grants covered by a global wildcard → null', () => {
		expect(findUncoveredGrant([entry('*', null)], [grant('report.read'), grant('report.feedback.create')])).toBeNull()
	})

	test('uncovered action → returns it', () => {
		const grants = [grant('report.read'), grant('report.delete')]
		expect(findUncoveredGrant([entry('report.read', null)], grants)).toEqual(grant('report.delete'))
	})

	test('omitted projectId requires a global permission', () => {
		// Issuer only holds report.read scoped to p1, not globally.
		expect(findUncoveredGrant([entry('report.read', 'p1')], [grant('report.read')])).toEqual(grant('report.read'))
	})

	test('per-grant projectId scopes the delegation check', () => {
		expect(findUncoveredGrant([entry('report.read', 'p1')], [grant('report.read', 'p1')])).toBeNull()
	})

	test('project-scoped grant not covered by a different project', () => {
		expect(findUncoveredGrant([entry('report.read', 'p2')], [grant('report.read', 'p1')]))
			.toEqual(grant('report.read', 'p1'))
	})

	test('a global permission covers a project-scoped grant', () => {
		expect(findUncoveredGrant([entry('report.*', null)], [grant('report.read', 'p1')])).toBeNull()
	})

	test('empty grants → null (nothing to cover)', () => {
		expect(findUncoveredGrant([entry('report.read', null)], [])).toBeNull()
	})
})

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
