/**
 * Typed request-time errors + a small authorization helper.
 *
 * These are the SHARED structural HTTP-error contract a server framework (trasa) maps without any
 * cross-package `instanceof`: each error exposes `{ httpStatus, type, message }` plus an optional
 * `issues` (validation detail) and an optional `loginUrl` (a human SSO bounce). A mapper reads those
 * fields structurally — it never imports these classes — so the shapes here and trasa's reader are the
 * single contract. They live in `@propustka/client` because `requirePermission` consumes an
 * `AuthContext` (a client type) and `loginUrl` is a request concept, not core logic.
 */

import type { Scope } from '@propustka/core'
import type { AuthContext } from './types'

/**
 * The structural HTTP-error shape. Anything thrown through a request pipeline that satisfies this can be
 * mapped to a Response without an `instanceof` check: `httpStatus` → the status, `type` → the error
 * envelope's `type`, `message` → its `message`, `issues` → optional detail, `loginUrl` → a human SSO
 * bounce target (present only on `LoginRequiredError`).
 */
export interface HttpError {
	readonly httpStatus: number
	readonly type: string
	readonly message: string
	readonly issues?: unknown
	readonly loginUrl?: string
}

/**
 * A human caller is not logged in and a redirect to SSO applies. `type: 'auth'`, status 401; `loginUrl`
 * is where the caller may 302 a browser to log in (it already carries the return `redirect` param).
 */
export class LoginRequiredError extends Error implements HttpError {
	readonly httpStatus = 401
	readonly type = 'auth'
	readonly loginUrl: string

	constructor(message: string, loginUrl: string) {
		super(message)
		this.name = 'LoginRequiredError'
		this.loginUrl = loginUrl
	}
}

/** A caller is unauthenticated with no SSO bounce (a machine / XHR). `type: 'auth'`, status 401. */
export class UnauthenticatedError extends Error implements HttpError {
	readonly httpStatus = 401
	readonly type = 'auth'

	constructor(message = 'authentication required') {
		super(message)
		this.name = 'UnauthenticatedError'
	}
}

/** A resolved caller lacks the required permission. `type: 'forbidden'`, status 403. */
export class ForbiddenError extends Error implements HttpError {
	readonly httpStatus = 403
	readonly type = 'forbidden'

	constructor(message = 'forbidden') {
		super(message)
		this.name = 'ForbiddenError'
	}
}

/**
 * Assert the caller may perform `action` (optionally within `scope`). Throws `ForbiddenError` when
 * `auth.can(action, scope)` is false; otherwise returns. The thrown error satisfies the structural
 * `HttpError` contract, so a pipeline maps it to a 403 without importing this module.
 */
export function requirePermission(auth: AuthContext, action: string, scope?: Scope): void {
	if (!auth.can(action, scope)) {
		throw new ForbiddenError(`missing permission: ${action}`)
	}
}
