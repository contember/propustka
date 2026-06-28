import type { AccessTokenClaims, PermissionEntry } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { buildAuthContext } from '../client'
import { ForbiddenError, type HttpError, LoginRequiredError, requirePermission, UnauthenticatedError } from '../errors'
import type { AuthContext } from '../types'
import { IamRpcStub } from './stub'

function ctxWith(perms: PermissionEntry[]): AuthContext {
	const claims: AccessTokenClaims = {
		iss: 'https://iam.example.com',
		aud: 'app-x',
		sub: 'pr-1',
		iat: 0,
		exp: 9_999_999_999,
		perms,
		ptype: 'user',
		label: 'alice@example.com',
	}
	return buildAuthContext(new IamRpcStub(), 'app-x', claims, 'req-1')
}

describe('typed errors expose the structural HttpError contract', () => {
	test('LoginRequiredError → 401 / auth / loginUrl', () => {
		const err = new LoginRequiredError('login', 'https://idp/auth/login?redirect=x')
		const structural: HttpError = err
		expect(structural.httpStatus).toBe(401)
		expect(structural.type).toBe('auth')
		expect(structural.message).toBe('login')
		expect(structural.loginUrl).toBe('https://idp/auth/login?redirect=x')
		expect(err instanceof Error).toBe(true)
	})

	test('UnauthenticatedError → 401 / auth, default message, no loginUrl', () => {
		const err = new UnauthenticatedError()
		const structural: HttpError = err
		expect(structural.httpStatus).toBe(401)
		expect(structural.type).toBe('auth')
		expect(structural.message).toBe('authentication required')
		expect(structural.loginUrl).toBeUndefined()
	})

	test('ForbiddenError → 403 / forbidden', () => {
		const err = new ForbiddenError('nope')
		expect(err.httpStatus).toBe(403)
		expect(err.type).toBe('forbidden')
		expect(err.message).toBe('nope')
	})
})

describe('requirePermission', () => {
	test('returns silently when the permission is held', () => {
		const auth = ctxWith([{ action: 'project.read', scope: null, source: 'grant' }])
		expect(() => requirePermission(auth, 'project.read')).not.toThrow()
	})

	test('throws ForbiddenError when the permission is missing', () => {
		const auth = ctxWith([{ action: 'project.read', scope: null, source: 'grant' }])
		expect(() => requirePermission(auth, 'project.write')).toThrow(ForbiddenError)
	})

	test('honours the scope argument (scoped grant)', () => {
		const auth = ctxWith([{ action: 'project.read', scope: { type: 'project', value: 'p1' }, source: 'grant' }])
		expect(() => requirePermission(auth, 'project.read', { type: 'project', value: 'p1' })).not.toThrow()
		expect(() => requirePermission(auth, 'project.read', { type: 'project', value: 'p2' })).toThrow(ForbiddenError)
	})
})
