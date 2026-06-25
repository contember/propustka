import { describe, expect, test } from 'bun:test'
import {
	buildCapabilityClaims,
	buildPrincipalClaims,
	type CapabilityTokenClaims,
	parseTokenClaims,
	principalClaimsToResolved,
	type PrincipalTokenClaims,
} from '../token'
import type { PermissionEntry } from '../types'

const ISS = 'https://propustka.example.com'

const perms: PermissionEntry[] = [
	{ action: '*', scope: null, source: 'bootstrap' },
	{ action: 'project.read', scope: { type: 'project', value: 'demo' }, source: 'grant' },
	{ action: 'report.*', scope: null, source: 'group:acme/core' },
]

function principalClaims(overrides: Partial<PrincipalTokenClaims> = {}): PrincipalTokenClaims {
	return {
		...buildPrincipalClaims({
			iss: ISS,
			app: 'example-app',
			principalId: 'user-1',
			type: 'user',
			label: 'a@b.cz',
			permissions: perms,
			issuedAt: 1000,
			expiresAt: 1300,
		}),
		...overrides,
	}
}

describe('buildPrincipalClaims', () => {
	test('maps app→aud, principalId→sub and carries the resolved permissions', () => {
		const claims = principalClaims()
		expect(claims.kind).toBe('principal')
		expect(claims.aud).toBe('example-app')
		expect(claims.sub).toBe('user-1')
		expect(claims.iss).toBe(ISS)
		expect(claims.iat).toBe(1000)
		expect(claims.exp).toBe(1300)
		expect(claims.ptype).toBe('user')
		expect(claims.perms).toEqual(perms)
	})
})

describe('parseTokenClaims — principal round-trip', () => {
	test('a built principal token parses back to identical claims', () => {
		const built = principalClaims()
		// Serialize → parse, exactly the JSON round-trip a JWT payload goes through.
		const onWire: unknown = JSON.parse(JSON.stringify(built))
		expect(parseTokenClaims(onWire)).toEqual(built)
	})

	test('parsed claims map into a ResolvedPrincipal the AuthContext consumes', () => {
		const parsed = parseTokenClaims(JSON.parse(JSON.stringify(principalClaims())))
		expect(parsed?.kind).toBe('principal')
		if (parsed?.kind !== 'principal') {
			throw new Error('expected principal')
		}
		expect(principalClaimsToResolved(parsed, 'req-9')).toEqual({
			id: 'user-1',
			type: 'user',
			label: 'a@b.cz',
			permissions: perms,
			requestId: 'req-9',
		})
	})
})

describe('parseTokenClaims — capability round-trip', () => {
	test('a built capability token parses back to identical claims', () => {
		const built: CapabilityTokenClaims = buildCapabilityClaims({
			iss: ISS,
			app: 'example-app',
			tokenId: 'cap-1',
			label: 'Client ACME — report Q2',
			caps: [{ action: 'report.read', resource: 'report:q2' }],
			issuedAt: 1000,
			expiresAt: 1300,
		})
		expect(parseTokenClaims(JSON.parse(JSON.stringify(built)))).toEqual(built)
	})

	test('a null label survives the round-trip', () => {
		const built = buildCapabilityClaims({
			iss: ISS,
			app: 'a',
			tokenId: 'cap-2',
			label: null,
			caps: [{ action: 'x', resource: 'y' }],
			issuedAt: 1,
			expiresAt: 2,
		})
		const parsed = parseTokenClaims(JSON.parse(JSON.stringify(built)))
		expect(parsed?.kind === 'capability' && parsed.label).toBeNull()
	})
})

describe('parseTokenClaims — rejects malformed', () => {
	test('unknown kind', () => {
		expect(parseTokenClaims({ ...principalClaims(), kind: 'other' })).toBeNull()
	})

	test('missing standard claim (aud)', () => {
		const { aud: _aud, ...rest } = principalClaims()
		expect(parseTokenClaims(rest)).toBeNull()
	})

	test('non-numeric exp', () => {
		expect(parseTokenClaims({ ...principalClaims(), exp: 'soon' })).toBeNull()
	})

	test('bad principal type', () => {
		expect(parseTokenClaims({ ...principalClaims(), ptype: 'robot' })).toBeNull()
	})

	test('malformed permission entry (missing action)', () => {
		expect(parseTokenClaims({ ...principalClaims(), perms: [{ scope: null, source: 'grant' }] })).toBeNull()
	})

	test('malformed permission source', () => {
		expect(
			parseTokenClaims({ ...principalClaims(), perms: [{ action: 'x', scope: null, source: 'nope' }] }),
		).toBeNull()
	})

	test('malformed scope (value not a string)', () => {
		expect(
			parseTokenClaims({
				...principalClaims(),
				perms: [{ action: 'x', scope: { type: 'project', value: 5 }, source: 'grant' }],
			}),
		).toBeNull()
	})

	test('capability with a non-string label', () => {
		expect(
			parseTokenClaims({
				iss: ISS,
				aud: 'a',
				sub: 'c',
				iat: 1,
				exp: 2,
				kind: 'capability',
				label: 7,
				caps: [],
			}),
		).toBeNull()
	})

	test('non-object payload', () => {
		expect(parseTokenClaims(null)).toBeNull()
		expect(parseTokenClaims('a string')).toBeNull()
	})
})
