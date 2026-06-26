import { type PermissionEntry, permits, type PrincipalType, SESSION_COOKIE } from '@propustka/core'
import { resolveCaller } from '../auth'
import { principalStatus } from '../db'
import type { Env } from '../env'
import { resolveUserPermissions } from '../resolve'
import { hashToken } from '../secret'
import type { Services } from '../services'
import type { AdminContext } from './handlers'
import {
	createGrant,
	createGroupMapping,
	createPolicy,
	createShareLink,
	deleteGrant,
	deleteGroupMapping,
	deletePolicy,
	deletePrincipal,
	getAppAccess,
	getAppSchema,
	getPrincipal,
	handleMe,
	invitePrincipal,
	listApiKeys,
	listApps,
	listAudit,
	listAuthLog,
	listGroupMappings,
	listPolicies,
	listPrincipals,
	listRoles,
	listShareLinks,
	patchPrincipal,
	provisionApiKey,
	putAppAccess,
	putAppSchema,
	revokeApiKey,
	revokeShareLink,
	rotateApiKey,
	updatePolicy,
} from './handlers'
import { error } from './http'

// The pinned sentinel action: only the `admin` role's `*` and bootstrap admins
// hold it. Scope-less → satisfied by a GLOBAL permission only (never a
// project-scoped grant).
const ADMIN_ACTION = 'iam.admin'

// propustka's own app id — the audience the admin caller is resolved against (the SSO session is
// minted for it in auth/routes.ts). The built-in `admin` role is cross-app, so a global admin grant
// still resolves here regardless.
const IAM_APP = 'propustka'

/**
 * The propustka-native admin credentials read off the request: a browser SSO session
 * (`px_session` cookie) and/or an `Authorization: Bearer` machine credential (a `px_`
 * admin/provisioning key). There is no Cloudflare Access JWT anymore.
 */
function extractCredentials(request: Request): {
	bearer: string | null
	session: string | null
	requestId: string
} {
	const bearer = readBearer(request.headers.get('Authorization'))
	const session = parseCookie(request.headers.get('Cookie'), SESSION_COOKIE)
	const requestId = request.headers.get('cf-ray') ?? crypto.randomUUID()
	return { bearer, session, requestId }
}

/** Read the token out of an `Authorization: Bearer <token>` header. Null when absent/non-bearer. */
function readBearer(header: string | null): string | null {
	if (header === null) {
		return null
	}
	const match = /^Bearer\s+(.+)$/i.exec(header.trim())
	return match ? (match[1]?.trim() ?? null) : null
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

/** The resolved admin (already authenticated; the `iam.admin` gate is applied by `handleAdmin`). */
interface ResolvedAdmin {
	id: string
	type: PrincipalType
	label: string | null
	permissions: PermissionEntry[]
}

type AdminResolution =
	| { ok: true; admin: ResolvedAdmin }
	| { ok: false; status: 401 | 403; reason: string }

/**
 * Resolve the admin caller from propustka-native credentials (no Cloudflare Access):
 *   - an `Authorization: Bearer px_<key>` machine credential (CI / provisioning) → `resolveCaller`
 *     (which also covers the local-dev bypass when no credential is presented);
 *   - else the browser's `px_session` SSO cookie → session → principal → resolved permissions.
 * Returns the caller + permissions; `handleAdmin` then enforces `iam.admin`. An ANONYMOUS credential
 * (a passthrough JWT / share link, no principal) is rejected — admin needs an accountable principal.
 */
async function resolveAdmin(
	services: Services,
	env: Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>,
	creds: { bearer: string | null; session: string | null; requestId: string },
): Promise<AdminResolution> {
	// Bearer credential (or no credential at all → local-dev bypass) goes through `resolveCaller`.
	if (creds.bearer !== null || creds.session === null) {
		const res = await resolveCaller(services, env, { app: IAM_APP, credential: creds.bearer, requestId: creds.requestId })
		if (!res.ok) {
			const status = res.reason === 'missing_token' || res.reason === 'invalid_token' ? 401 : 403
			return { ok: false, status, reason: res.reason }
		}
		if (res.caller.type === undefined) {
			return { ok: false, status: 403, reason: 'not_allowed' }
		}
		return { ok: true, admin: { id: res.caller.id, type: res.caller.type, label: res.caller.label, permissions: res.caller.permissions } }
	}

	// Browser SSO session: validate the opaque `px_session`, resolve the principal's permissions for
	// propustka's own app (groups don't apply — there is no CF identity cookie here).
	const session = await services.db.getActiveSessionByHash(await hashToken(creds.session))
	if (!session) {
		return { ok: false, status: 401, reason: 'invalid_session' }
	}
	const principal = await services.db.getPrincipalById(session.principal_id)
	if (!principal) {
		return { ok: false, status: 401, reason: 'invalid_session' }
	}
	if (principalStatus(principal) === 'disabled') {
		return { ok: false, status: 403, reason: 'disabled' }
	}
	const { permissions } = await resolveUserPermissions({
		db: services.db,
		identity: services.identity,
		principal,
		cookie: null,
		origin: null,
		bootstrapAdmins: services.config.bootstrapAdmins,
		app: IAM_APP,
	})
	return { ok: true, admin: { id: principal.id, type: principal.type, label: principal.label, permissions } }
}

/**
 * Handle any `/admin/*` request. The caller is resolved from propustka-native credentials
 * (`px_session` SSO cookie or a `px_` bearer) and every handler runs only after `can('iam.admin')`
 * passes in-Worker (scope-less → global only). Returns 401 when the caller can't be authenticated,
 * 403 when authenticated but not an admin.
 */
export async function handleAdmin(
	request: Request,
	services: Services,
	env: Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>,
	ctx: ExecutionContext,
): Promise<Response> {
	const url = new URL(request.url)
	const creds = extractCredentials(request)

	// CSRF defense: reject cross-origin state-changing writes before touching the DB.
	const crossOrigin = rejectCrossOrigin(request, url)
	if (crossOrigin) {
		return crossOrigin
	}

	// Backstop: resolution and the handlers touch D1, which can throw on a transient
	// error. Map any unexpected throw to a 500 (never leak internals) so the admin
	// surface degrades gracefully instead of surfacing a raw rejection.
	try {
		const resolution = await resolveAdmin(services, env, creds)
		if (!resolution.ok) {
			return error(resolution.status, resolution.reason)
		}
		if (!permits(resolution.admin.permissions, ADMIN_ACTION)) {
			return error(403, 'admin permission required')
		}

		const c: AdminContext = {
			services,
			request,
			url,
			admin: resolution.admin,
			app: IAM_APP,
			requestId: creds.requestId,
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
	const [resource, idOrSub, action, subId] = segments

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

		case 'group-mappings':
			if (idOrSub === undefined) {
				if (method === 'GET') return listGroupMappings(c)
				if (method === 'POST') return createGroupMapping(c)
				return methodNotAllowed()
			}
			return method === 'DELETE' ? deleteGroupMapping(c, idOrSub) : methodNotAllowed()

		case 'roles':
			return method === 'GET' ? listRoles(c) : methodNotAllowed()

		case 'apps':
			// GET /admin/apps                          → list configured app ids
			// GET|PUT  /admin/apps/:app/schema         → read / reconcile vocabulary
			// GET|PUT  /admin/apps/:app/access         → read / reconcile CF Access edge rules
			// GET|POST /admin/apps/:app/policies       → list / create custom policies
			// PUT|DELETE /admin/apps/:app/policies/:key → update / delete a custom policy
			if (idOrSub === undefined) {
				return method === 'GET' ? listApps(c) : methodNotAllowed()
			}
			if (action === 'schema') {
				if (method === 'GET') return getAppSchema(c, idOrSub)
				if (method === 'PUT') return putAppSchema(c, idOrSub)
				return methodNotAllowed()
			}
			if (action === 'access') {
				if (method === 'GET') return getAppAccess(c, idOrSub)
				if (method === 'PUT') return putAppAccess(c, idOrSub)
				return methodNotAllowed()
			}
			if (action === 'policies') {
				if (subId === undefined) {
					if (method === 'GET') return listPolicies(c, idOrSub)
					if (method === 'POST') return createPolicy(c, idOrSub)
					return methodNotAllowed()
				}
				if (method === 'PUT') return updatePolicy(c, idOrSub, subId)
				if (method === 'DELETE') return deletePolicy(c, idOrSub, subId)
				return methodNotAllowed()
			}
			return error(404, 'not found')

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

		case 'share-links':
			if (idOrSub === undefined) {
				if (method === 'GET') return listShareLinks(c)
				if (method === 'POST') return createShareLink(c)
				return methodNotAllowed()
			}
			return method === 'DELETE' ? revokeShareLink(c, idOrSub) : methodNotAllowed()

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
