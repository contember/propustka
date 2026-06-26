import { describe, expect, test } from 'bun:test'
import { accessClaimsToResolved, type AccessTokenClaims, buildAccessClaims, parseAccessClaims } from '../token'
import type { PermissionEntry } from '../types'

const ISS = 'https://propustka.example.com'

const perms: PermissionEntry[] = [
	{ action: '*', scope: null, source: 'bootstrap' },
	{ action: 'project.read', scope: { type: 'project', value: 'demo' }, source: 'grant' },
	{ action: 'report.*', scope: null, source: 'group:acme/core' },
]

function principalClaims(overrides: Partial<AccessTokenClaims> = {}): AccessTokenClaims {
	return {
		...buildAccessClaims({
			iss: ISS,
			app: 'example-app',
			subject: 'user-1',
			type: 'user',
			label: 'a@b.cz',
			permissions: perms,
			issuedAt: 1000,
			expiresAt: 1300,
		}),
		...overrides,
	}
}

describe('buildAccessClaims', () => {
	test('maps app→aud, subject→sub, type→ptype and carries the resolved permissions — no `kind`', () => {
		const claims = principalClaims()
		expect('kind' in claims).toBe(false)
		expect(claims.aud).toBe('example-app')
		expect(claims.sub).toBe('user-1')
		expect(claims.iss).toBe(ISS)
		expect(claims.iat).toBe(1000)
		expect(claims.exp).toBe(1300)
		expect(claims.ptype).toBe('user')
		expect(claims.perms).toEqual(perms)
	})

	test('an anonymous token omits ptype and may carry a null label', () => {
		const claims = buildAccessClaims({
			iss: ISS,
			app: 'a',
			subject: 'cred-1',
			label: null,
			permissions: [{ action: 'report.read', scope: { type: 'report', value: 'q2' }, source: 'grant' }],
			issuedAt: 1,
			expiresAt: 2,
		})
		expect(claims.ptype).toBeUndefined()
		expect(claims.label).toBeNull()
	})
})

describe('parseAccessClaims — principal round-trip', () => {
	test('a built principal token parses back to identical claims', () => {
		const built = principalClaims()
		// Serialize → parse, exactly the JSON round-trip a JWT payload goes through.
		const onWire: unknown = JSON.parse(JSON.stringify(built))
		expect(parseAccessClaims(onWire)).toEqual(built)
	})

	test('parsed claims map into a ResolvedPrincipal the AuthContext consumes', () => {
		const parsed = parseAccessClaims(JSON.parse(JSON.stringify(principalClaims())))
		expect(parsed?.ptype).toBe('user')
		expect(parsed && accessClaimsToResolved(parsed, 'req-9')).toEqual({
			id: 'user-1',
			type: 'user',
			label: 'a@b.cz',
			permissions: perms,
			requestId: 'req-9',
		})
	})
})

describe('parseAccessClaims — anonymous round-trip', () => {
	test('an anonymous (no-ptype) token round-trips, and resolves to no principal', () => {
		const built = buildAccessClaims({
			iss: ISS,
			app: 'example-app',
			subject: 'cred-1',
			label: 'Client ACME — report Q2',
			permissions: [{ action: 'report.read', scope: { type: 'report', value: 'q2' }, source: 'grant' }],
			issuedAt: 1000,
			expiresAt: 1300,
		})
		const parsed = parseAccessClaims(JSON.parse(JSON.stringify(built)))
		expect(parsed).toEqual(built)
		expect(parsed && accessClaimsToResolved(parsed, 'req-1')).toBeNull()
	})

	test('a null label survives the round-trip', () => {
		const built = buildAccessClaims({
			iss: ISS,
			app: 'a',
			subject: 'cred-2',
			label: null,
			permissions: [{ action: 'x', scope: null, source: 'grant' }],
			issuedAt: 1,
			expiresAt: 2,
		})
		expect(parseAccessClaims(JSON.parse(JSON.stringify(built)))?.label).toBeNull()
	})
})

describe('parseAccessClaims — rejects malformed', () => {
	test('missing standard claim (aud)', () => {
		const { aud: _aud, ...rest } = principalClaims()
		expect(parseAccessClaims(rest)).toBeNull()
	})

	test('non-numeric exp', () => {
		expect(parseAccessClaims({ ...principalClaims(), exp: 'soon' })).toBeNull()
	})

	test('bad principal type', () => {
		expect(parseAccessClaims({ ...principalClaims(), ptype: 'robot' })).toBeNull()
	})

	test('missing perms', () => {
		const { perms: _perms, ...rest } = principalClaims()
		expect(parseAccessClaims(rest)).toBeNull()
	})

	test('malformed permission entry (missing action)', () => {
		expect(parseAccessClaims({ ...principalClaims(), perms: [{ scope: null, source: 'grant' }] })).toBeNull()
	})

	test('malformed permission source', () => {
		expect(parseAccessClaims({ ...principalClaims(), perms: [{ action: 'x', scope: null, source: 'nope' }] })).toBeNull()
	})

	test('malformed scope (value not a string)', () => {
		expect(
			parseAccessClaims({
				...principalClaims(),
				perms: [{ action: 'x', scope: { type: 'project', value: 5 }, source: 'grant' }],
			}),
		).toBeNull()
	})

	test('a non-string label', () => {
		expect(parseAccessClaims({ ...principalClaims(), label: 7 })).toBeNull()
	})

	test('non-object payload', () => {
		expect(parseAccessClaims(null)).toBeNull()
		expect(parseAccessClaims('a string')).toBeNull()
	})
})
