import { permits } from '@propustka/core'
import { principalFromOutcome, resolveRequest } from '../auth'
import type { Services } from '../services'
import type { AdminContext } from './handlers'
import {
	createCapability,
	createGrant,
	createGroupMapping,
	createProject,
	deleteGrant,
	deleteGroupMapping,
	deletePrincipal,
	getPrincipal,
	handleMe,
	invitePrincipal,
	listApiKeys,
	listAudit,
	listAuthLog,
	listCapabilities,
	listGroupMappings,
	listPrincipals,
	listProjects,
	listRoles,
	patchPrincipal,
	provisionApiKey,
	revokeApiKey,
	revokeCapability,
	rotateApiKey,
	updateProject,
} from './handlers'
import { error } from './http'

// The pinned sentinel action: only the `admin` role's `*` and bootstrap admins
// hold it. Scope-less → satisfied by a GLOBAL permission only (never a
// project-scoped grant).
const ADMIN_ACTION = 'iam.admin'

/**
 * Extract the forwarded Access credentials from the incoming admin request. The
 * admin SPA runs behind Access, so the same headers/cookie an app forwards are
 * present here (Cloudflare injects `Cf-Access-Jwt-Assertion`; the browser carries
 * the `CF_Authorization` cookie).
 */
function extractCredentials(request: Request, url: URL): {
	token: string | null
	cookie: string | null
	origin: string | null
	requestId: string
} {
	const token = request.headers.get('Cf-Access-Jwt-Assertion')
	const cookie = parseCookie(request.headers.get('Cookie'), 'CF_Authorization')
	const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID()
	return { token, cookie, origin: url.origin, requestId }
}

function parseCookie(header: string | null, name: string): string | null {
	if (!header) {
		return null
	}
	for (const part of header.split(';')) {
		const eq = part.indexOf('=')
		if (eq === -1) {
			continue
		}
		if (part.slice(0, eq).trim() === name) {
			return part.slice(eq + 1).trim()
		}
	}
	return null
}

// State-changing HTTP methods. GET/HEAD are safe (no side effects) and are
// exempt from the same-origin check below.
const STATE_CHANGING_METHODS = new Set(['POST', 'PATCH', 'DELETE'])

/**
 * In-app CSRF defense: reject state-changing `/admin/*` requests that don't
 * originate from this Worker's own origin. The admin SPA is served same-origin by
 * this same Worker, so a legitimate browser fetch carries an `Origin` (or at least
 * `Referer`) matching `url.origin` for free; a cross-site forgery cannot forge
 * either to a same-origin value. This complements the Access edge + the cookie's
 * SameSite attribute (which this Worker can't verify and which may be `None` under
 * some Access configs). Returns `null` when allowed.
 */
function rejectCrossOrigin(request: Request, url: URL): Response | null {
	if (!STATE_CHANGING_METHODS.has(request.method)) {
		return null
	}
	const origin = request.headers.get('Origin')
	if (origin !== null) {
		return origin === url.origin ? null : error(403, 'cross-origin request rejected')
	}
	// No `Origin` (some same-origin requests omit it) → fall back to `Referer`.
	const referer = request.headers.get('Referer')
	if (referer !== null) {
		const refererOrigin = originOf(referer)
		return refererOrigin === url.origin ? null : error(403, 'cross-origin request rejected')
	}
	// Neither header present on a state-changing request → reject.
	return error(403, 'cross-origin request rejected')
}

// Parse the origin from a URL string; null if it isn't a valid absolute URL.
function originOf(value: string): string | null {
	try {
		return new URL(value).origin
	} catch {
		return null
	}
}

/**
 * Handle any `/admin/*` request. Beyond the Access policy at the edge, every
 * handler re-checks `can('iam.admin')` in-Worker (scope-less → global only), so a
 * misconfigured Access policy can't expose admin writes. Returns 401 when the
 * caller can't be authenticated, 403 when authenticated but not an admin.
 */
export async function handleAdmin(request: Request, services: Services, ctx: ExecutionContext): Promise<Response> {
	const url = new URL(request.url)
	const creds = extractCredentials(request, url)

	// CSRF defense: reject cross-origin state-changing writes before touching the DB.
	const crossOrigin = rejectCrossOrigin(request, url)
	if (crossOrigin) {
		return crossOrigin
	}

	// Backstop: resolveRequest and the handlers touch D1, which can throw on a
	// transient error. Map any unexpected throw to a 500 (never leak internals) so
	// the admin surface degrades gracefully instead of surfacing a raw rejection.
	try {
		const outcome = await resolveRequest(services, {
			app: 'iam-admin',
			token: creds.token,
			cookie: creds.cookie,
			origin: creds.origin,
			requestId: creds.requestId,
		})

		if (!outcome.result.ok) {
			// missing/invalid token → 401; unknown_principal/disabled → 403.
			const status = outcome.result.reason === 'missing_token' || outcome.result.reason === 'invalid_token' ? 401 : 403
			return error(status, outcome.result.reason)
		}

		const resolved = principalFromOutcome(outcome)
		if (!resolved || !permits(resolved.permissions, ADMIN_ACTION)) {
			return error(403, 'admin permission required')
		}

		const c: AdminContext = {
			services,
			request,
			url,
			admin: { id: resolved.id, label: outcome.result.principal.label, permissions: resolved.permissions },
			app: outcome.verifiedApp ?? 'iam-admin',
			outcome,
			authInput: { token: creds.token, cookie: creds.cookie, origin: creds.origin, requestId: creds.requestId },
			ctx,
		}

		return await dispatch(c)
	} catch (err) {
		console.error('admin request failed', err)
		return error(500, 'internal error')
	}
}

// Path segments after '/admin/'. Returns the matched handler or a 404/405.
async function dispatch(c: AdminContext): Promise<Response> {
	const method = c.request.method
	const segments = c.url.pathname.replace(/^\/admin\/?/, '').split('/').filter(Boolean)
	const [resource, idOrSub, action] = segments

	switch (resource) {
		case 'me':
			return method === 'GET' ? handleMe(c) : methodNotAllowed()

		case 'principals':
			if (idOrSub === undefined) {
				if (method === 'GET') return listPrincipals(c)
				if (method === 'POST') return invitePrincipal(c)
				return methodNotAllowed()
			}
			if (method === 'GET') return getPrincipal(c, idOrSub)
			if (method === 'DELETE') return deletePrincipal(c, idOrSub)
			if (method === 'PATCH') return patchPrincipal(c, idOrSub)
			return methodNotAllowed()

		case 'grants':
			if (idOrSub === undefined) {
				return method === 'POST' ? createGrant(c) : methodNotAllowed()
			}
			return method === 'DELETE' ? deleteGrant(c, idOrSub) : methodNotAllowed()

		case 'projects':
			if (idOrSub === undefined) {
				if (method === 'GET') return listProjects(c)
				if (method === 'POST') return createProject(c)
				return methodNotAllowed()
			}
			return method === 'PATCH' ? updateProject(c, idOrSub) : methodNotAllowed()

		case 'group-mappings':
			if (idOrSub === undefined) {
				if (method === 'GET') return listGroupMappings(c)
				if (method === 'POST') return createGroupMapping(c)
				return methodNotAllowed()
			}
			return method === 'DELETE' ? deleteGroupMapping(c, idOrSub) : methodNotAllowed()

		case 'roles':
			return method === 'GET' ? listRoles() : methodNotAllowed()

		case 'api-keys':
			if (idOrSub === undefined) {
				if (method === 'GET') return listApiKeys(c)
				if (method === 'POST') return provisionApiKey(c)
				return methodNotAllowed()
			}
			if (action === 'rotate') {
				return method === 'POST' ? rotateApiKey(c, idOrSub) : methodNotAllowed()
			}
			return method === 'DELETE' ? revokeApiKey(c, idOrSub) : methodNotAllowed()

		case 'capabilities':
			if (idOrSub === undefined) {
				if (method === 'GET') return listCapabilities(c)
				if (method === 'POST') return createCapability(c)
				return methodNotAllowed()
			}
			return method === 'DELETE' ? revokeCapability(c, idOrSub) : methodNotAllowed()

		case 'audit':
			return method === 'GET' ? listAudit(c) : methodNotAllowed()

		case 'auth-log':
			return method === 'GET' ? listAuthLog(c) : methodNotAllowed()

		default:
			return error(404, 'not found')
	}
}

function methodNotAllowed(): Response {
	return error(405, 'method not allowed')
}
