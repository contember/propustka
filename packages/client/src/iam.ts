/**
 * `createIam` — the single request-time entry point apps use instead of hand-rolling auth.
 *
 * `createIam(env, opts)` reads the standard propustka env (`IAM` binding, `PROPUSTKA_URL` issuer,
 * `DEV`, app id from `opts.appId` ?? `PROPUSTKA_APP_ID`) and returns an `Iam` that bundles:
 *   - the existing MANAGEMENT surface (`listPrincipals` / `issueKey` / `issueJwt` / `revokeKey`),
 *     delegated to `IamClient` off-local or `FakeIamClient` in dev;
 *   - middleware FACTORIES (`authMiddleware` / `apiKeyMiddleware` / `capabilityMiddleware`) that produce
 *     functions of the shared `Middleware<Ctx>` shape (see `middleware.ts`);
 *   - a dev login handler (`devLoginHandler`) that sets the persona cookie.
 *
 * Dev-aware: when `env.DEV` is truthy the whole thing is backed by `FakeIamClient` + synthetic persona
 * contexts (no IAM Worker, no SSO); off-local it is backed by the real `IAM` binding (`PropustkaAuth` +
 * `IamClient`). This generalizes the per-app `app/iam.ts` seams (revizor / poplach / opice) into one SDK.
 */

import { type AppGates, type PermissionEntry, permits, type PrincipalType, type Scope, scopedValues } from '@propustka/core'
import type { IamRpc } from '@propustka/core'
import { IamClient } from './client'
import { FakeIamClient, type FakePersona } from './fake'
import type { AuthCarrier, Middleware } from './middleware'
import { PropustkaAuth, type SessionAuthResult } from './session'
import type {
	AuthContext,
	IssuedJwt,
	IssuedKey,
	IssueFailure,
	IssueJwtRequest,
	IssueKeyRequest,
	ListPrincipalsFailure,
	PrincipalIdentity,
	PrincipalList,
	RevokedKey,
	RevokeFailure,
} from './types'

// ── Public config surfaces ──────────────────────────────────────────────────────

/** The env `createIam` reads. An app's Worker `Env` satisfies it structurally (extra fields are fine). */
export interface IamEnv {
	/** The IAM Worker service binding (off-local). Typed as the `IamRpc` contract — never the Worker. */
	IAM?: IamRpc
	/** propustka's origin — the `PropustkaAuth` issuer (token `iss` + the `/auth/login` base). Off-local. */
	PROPUSTKA_URL?: string
	/** Fallback app id when `opts.appId` is omitted. */
	PROPUSTKA_APP_ID?: string
	/** Dev flag — truthy selects the `FakeIamClient` + persona path (no IAM Worker, no SSO). */
	DEV?: string | boolean
}

/**
 * A dev persona — an identity plus its permission grants, evaluated by `makeDevContext` against the
 * real `permits`/`scopedValues` matchers so the dev path enforces scope EXACTLY like prod. Keyed by
 * email in `opts.devPersonas`. `permissions` carry no `source` (it is data, not a resolution origin).
 */
export interface PersonaSpec {
	id: string
	label: string
	/** 'user' or 'service'; any non-'service' value resolves to 'user'. */
	type: string
	permissions: Array<{ action: string; scope: Scope | null }>
}

/** Options for `createIam`. `appId` falls back to `env.PROPUSTKA_APP_ID`. */
export interface CreateIamOptions {
	/** The propustka app id (baked in so it can never be mistyped). Falls back to `env.PROPUSTKA_APP_ID`. */
	appId?: string
	/** Dev persona roster keyed by email — the local people directory + the synthetic-context source. */
	devPersonas?: Record<string, PersonaSpec>
	/** Persona used in dev when no `?__as=` / cookie selector is present (e.g. the admin). */
	devDefaultPersona?: string
	/** The cookie the dev persona-switch reads/writes. Default `propustka_dev_principal`. */
	devPersonaCookie?: string
}

/** Failure half of `SessionAuthResult` — handed to `authMiddleware`'s `onError` hook. */
export type AuthFailure = Extract<SessionAuthResult, { ok: false }>

/** Config for `iam.authMiddleware`. */
export interface AuthMiddlewareConfig {
	/** The ordered per-path gate rules enforced in-process (the successor to the CF Access edge). */
	gates: AppGates
	/**
	 * Optional override for a failed authentication. Returns a Response to short-circuit with your own
	 * shape, or `undefined` to fall through to the default (302/401-JSON for a human miss; status+JSON
	 * otherwise). Never called on success.
	 */
	onError?: (request: Request, failure: AuthFailure) => Response | undefined | Promise<Response | undefined>
}

/** Config for `iam.apiKeyMiddleware`. */
export interface ApiKeyMiddlewareConfig {
	/**
	 * App-side key → subject resolver (the lookup stays app-owned). Return the resolved machine
	 * principal `{ id, label }`, or `null` to reject (→ 401). Receives the raw key and the request.
	 */
	resolve: (key: string, request: Request) => Promise<{ id: string; label: string } | null>
	/** Header to read a `sentry_key=…` list (or a bare/Bearer value) from. Default `X-Sentry-Auth`. */
	header?: string
	/** Query param to read the key from. Default `sentry_key`. */
	query?: string
}

/** Config for `iam.capabilityMiddleware`. */
export interface CapabilityMiddlewareConfig {
	/** Query param carrying the capability/share token. Default `token`. */
	query?: string
	/** Cookie carrying the capability/share token. Default `opice_read`. */
	cookie?: string
}

// ── makeDevContext + persona helpers ─────────────────────────────────────────────

/** Narrow a `PersonaSpec.type` (a plain string) to a `PrincipalType`; anything but 'service' is 'user'. */
function principalType(type: string): PrincipalType {
	return type === 'service' ? 'service' : 'user'
}

/** A persona's grants as `PermissionEntry[]` (stamped `source: 'grant'`) for the `permits` matchers. */
function personaEntries(persona: PersonaSpec): PermissionEntry[] {
	return persona.permissions.map((grant) => ({ action: grant.action, scope: grant.scope, source: 'grant' }))
}

/**
 * Build a synthetic `AuthContext` for a dev persona. `can`/`scopedTo` evaluate against the persona's
 * grants using core's `permits`/`scopedValues` — the SAME matchers the real (token-backed) context
 * uses, so dev enforces scope identically to prod. `audit` is a no-op (no IAM Worker locally).
 */
export function makeDevContext(persona: PersonaSpec): AuthContext {
	const entries = personaEntries(persona)
	const principal: PrincipalIdentity = { id: persona.id, type: principalType(persona.type), label: persona.label }
	return {
		ok: true,
		principal,
		can: (action, scope) => permits(entries, action, scope),
		scopedTo: (action, dimension) => scopedValues(entries, action, dimension),
		audit: () => Promise.resolve(),
	}
}

/** Map the public `PersonaSpec` roster to the `FakeIamClient`'s `FakePersona` shape (for `listPrincipals`). */
function toFakePersonas(personas: Record<string, PersonaSpec> | undefined): Record<string, FakePersona> | undefined {
	if (personas === undefined) {
		return undefined
	}
	const out: Record<string, FakePersona> = {}
	for (const [email, persona] of Object.entries(personas)) {
		out[email] = { id: persona.id, label: persona.label, type: principalType(persona.type), permissions: personaEntries(persona) }
	}
	return out
}

// ── Synthetic contexts (machine / capability) ────────────────────────────────────

/**
 * A minimal MACHINE `AuthContext` for an api-key caller the app's `resolve` already authorized: the key
 * IS the authorization, so `can()` is permissive (no per-action checks) and `scopedTo()` is unrestricted.
 * Matches how ingest treats a resolved DSN/key today. `audit` is a no-op (the principal is app-owned).
 */
function machineContext(subject: { id: string; label: string }): AuthContext {
	const principal: PrincipalIdentity = { id: subject.id, type: 'service', label: subject.label }
	return {
		ok: true,
		principal,
		can: () => true,
		scopedTo: () => null,
		audit: () => Promise.resolve(),
	}
}

/** An OPEN capability context for dev — a present token grants everything (the local share gate is open). */
function openCapabilityContext(): AuthContext {
	return {
		ok: true,
		principal: null,
		can: () => true,
		scopedTo: () => null,
		audit: () => Promise.resolve(),
	}
}

// ── Small request/response helpers ───────────────────────────────────────────────

/** True when the request looks like a document navigation (so a human miss should 302 to SSO). */
function wantsHtml(request: Request): boolean {
	return (request.headers.get('Accept') ?? '').includes('text/html')
}

/** A JSON error envelope `{ error: { type, message, loginUrl? } }` with the given status. */
function errorResponse(status: number, type: string, message: string, loginUrl?: string): Response {
	const error = loginUrl === undefined ? { type, message } : { type, message, loginUrl }
	return new Response(JSON.stringify({ error }), { status, headers: { 'content-type': 'application/json' } })
}

/** A leak-free 404 — the capability surface's only failure (never a 401/403 that reveals a resource). */
function notFound(): Response {
	return new Response('Not Found', { status: 404 })
}

/** A short, non-leaky message for a non-human auth failure reason. */
function failureMessage(reason: AuthFailure['reason']): string {
	switch (reason) {
		case 'no_rule':
			return 'no matching access rule'
		case 'no_credential':
			return 'a credential is required'
		case 'invalid_key':
			return 'invalid credential'
		case 'unknown_principal':
			return 'unknown principal'
		case 'disabled':
			return 'principal disabled'
		default:
			return 'not authenticated'
	}
}

/** Read the token out of an `Authorization: Bearer <token>` header. Null when absent/non-bearer. */
function readBearer(header: string | null): string | null {
	if (header === null) {
		return null
	}
	const match = /^Bearer\s+(.+)$/i.exec(header.trim())
	return match ? (match[1]?.trim() ?? null) : null
}

/** URL-decode a value, falling back to the raw value on malformed input (never throws). */
function safeDecode(value: string): string {
	try {
		return decodeURIComponent(value)
	} catch {
		return value
	}
}

/** Read a single cookie value out of a raw Cookie header. Null when absent. */
function readCookie(header: string | null, name: string): string | null {
	if (!header) {
		return null
	}
	for (const part of header.split(';')) {
		const eq = part.indexOf('=')
		if (eq !== -1 && part.slice(0, eq).trim() === name) {
			return part.slice(eq + 1).trim()
		}
	}
	return null
}

/**
 * Pull an api key from (in order): `Authorization: Bearer …`, the configured header (default
 * `X-Sentry-Auth`, parsed for a `sentry_key=…` list, else taken bare/Bearer-stripped), then the
 * configured query param (default `sentry_key`). Null when none is present.
 */
function extractApiKey(request: Request, headerName: string, queryName: string): string | null {
	const bearer = readBearer(request.headers.get('Authorization'))
	if (bearer !== null) {
		return bearer
	}
	const headerValue = request.headers.get(headerName)
	if (headerValue !== null) {
		const sentry = /sentry_key=([^,\s]+)/i.exec(headerValue)
		if (sentry?.[1] !== undefined) {
			return decodeURIComponent(sentry[1])
		}
		const bare = readBearer(headerValue) ?? headerValue.trim()
		if (bare !== '') {
			return bare
		}
	}
	const fromQuery = new URL(request.url).searchParams.get(queryName)
	return fromQuery !== null && fromQuery !== '' ? fromQuery : null
}

/** Pull a capability/share token from the configured query param, then the configured cookie. */
function extractCapabilityToken(request: Request, queryName: string, cookieName: string): string | null {
	const fromQuery = new URL(request.url).searchParams.get(queryName)
	if (fromQuery !== null && fromQuery !== '') {
		return fromQuery
	}
	return readCookie(request.headers.get('Cookie'), cookieName)
}

// ── Iam ──────────────────────────────────────────────────────────────────────────

/** Mode-specific deps: dev needs nothing; off-local needs the binding + issuer (so no `!` later). */
type IamMode = { dev: true } | { dev: false; binding: IamRpc; issuer: string }

/** Internal construction config — `createIam` assembles this; apps never build it directly. */
interface IamConfig {
	management: IamClient | FakeIamClient
	mode: IamMode
	appId: string
	devPersonas: Record<string, PersonaSpec> | undefined
	devDefaultPersona: string | undefined
	devPersonaCookie: string
}

/**
 * The request-time IAM surface. Build it with `createIam` (the only intended entry point — the
 * constructor takes an internal config). Bundles the management methods, the middleware factories, and
 * the dev login handler — all bound to the env + app id resolved at construction.
 */
export class Iam {
	private readonly management: IamClient | FakeIamClient
	private readonly mode: IamMode
	private readonly appId: string
	private readonly devPersonas: Record<string, PersonaSpec> | undefined
	private readonly devDefaultPersona: string | undefined
	private readonly devPersonaCookie: string

	/** @internal — use `createIam`. */
	constructor(config: IamConfig) {
		this.management = config.management
		this.mode = config.mode
		this.appId = config.appId
		this.devPersonas = config.devPersonas
		this.devDefaultPersona = config.devDefaultPersona
		this.devPersonaCookie = config.devPersonaCookie
	}

	// ── Management surface (delegated to the real / fake client) ──────────────────

	listPrincipals(req: Request): Promise<PrincipalList | ListPrincipalsFailure> {
		return this.management.listPrincipals(req)
	}

	issueKey(req: Request, input: IssueKeyRequest): Promise<IssuedKey | IssueFailure> {
		return this.management.issueKey(req, input)
	}

	issueJwt(req: Request, input: IssueJwtRequest): Promise<IssuedJwt | IssueFailure> {
		return this.management.issueJwt(req, input)
	}

	revokeKey(req: Request, id: string): Promise<RevokedKey | RevokeFailure> {
		return this.management.revokeKey(req, id)
	}

	// ── Middleware factories ──────────────────────────────────────────────────────

	/**
	 * Front-door auth middleware. Resolves the caller (in dev: the persona from `?__as=` / the cookie /
	 * the default; off-local: `PropustkaAuth(...).authenticate`), then:
	 *   - success → set `ctx.auth`; if a fresh `px_token` was minted, wrap `next()` and append its
	 *     `Set-Cookie`; then continue;
	 *   - human miss (failure WITH a `loginUrl`) → 302 to the login URL for a document navigation,
	 *     else 401 JSON `{ error: { type: 'auth', message, loginUrl } }`; short-circuit;
	 *   - other failure → `result.status` + JSON `{ error: { type: reason, message } }`; short-circuit.
	 * An `onError` override (when provided) gets first refusal on any failure.
	 */
	authMiddleware<Ctx extends AuthCarrier>(cfg: AuthMiddlewareConfig): Middleware<Ctx> {
		return async (request, ctx, next) => {
			const result = this.mode.dev
				? this.resolveDevPersona(request)
				: await new PropustkaAuth(this.mode.binding, this.appId, { issuer: this.mode.issuer, gates: cfg.gates }).authenticate(request)

			if (result.ok) {
				ctx.auth = result.context
				if (result.setCookie === undefined) {
					return next()
				}
				// Wrap next(): mint rode along, so attach the fresh px_token to the downstream Response.
				const response = await next()
				const withCookie = new Response(response.body, response)
				withCookie.headers.append('Set-Cookie', result.setCookie)
				return withCookie
			}

			if (cfg.onError !== undefined) {
				const override = await cfg.onError(request, result)
				if (override !== undefined) {
					return override
				}
			}

			if (result.loginUrl !== undefined) {
				// `loginUrl` already carries the return `redirect` param (PropustkaAuth built it).
				if (wantsHtml(request)) {
					return new Response(null, { status: 302, headers: { location: result.loginUrl } })
				}
				return errorResponse(401, 'auth', 'authentication required', result.loginUrl)
			}
			return errorResponse(result.status, result.reason, failureMessage(result.reason))
		}
	}

	/**
	 * Machine / anonymous-key middleware. Extracts a key (Bearer → header → query), calls the app-side
	 * `resolve`, and on a hit sets `ctx.auth` to a permissive machine context (the key IS the
	 * authorization). A missing key or a `null` resolve → 401 JSON. Short-circuits on failure.
	 */
	apiKeyMiddleware<Ctx extends AuthCarrier>(cfg: ApiKeyMiddlewareConfig): Middleware<Ctx> {
		const headerName = cfg.header ?? 'X-Sentry-Auth'
		const queryName = cfg.query ?? 'sentry_key'
		return async (request, ctx, next) => {
			const key = extractApiKey(request, headerName, queryName)
			if (key === null) {
				return errorResponse(401, 'auth', 'missing api key')
			}
			const subject = await cfg.resolve(key, request)
			if (subject === null) {
				return errorResponse(401, 'auth', 'invalid api key')
			}
			ctx.auth = machineContext(subject)
			return next()
		}
	}

	/**
	 * Capability / share-token middleware (e.g. opice `/s/*`). Reads the token from the query param then
	 * the cookie, redeems it over the IAM binding (`mintFromKey` — the propustka-native capability is a
	 * standalone `px_` credential), and on success sets `ctx.auth` to the redeemed (anonymous) context
	 * whose `can(action, scope)` does exact-resource checks via `permits`. ANY failure → 404 (never a
	 * leaky 401/403). In dev a present token grants an open context (the local share gate is open).
	 */
	capabilityMiddleware<Ctx extends AuthCarrier>(cfg: CapabilityMiddlewareConfig = {}): Middleware<Ctx> {
		const queryName = cfg.query ?? 'token'
		const cookieName = cfg.cookie ?? 'opice_read'
		return async (request, ctx, next) => {
			const token = extractCapabilityToken(request, queryName, cookieName)
			if (token === null) {
				return notFound()
			}
			if (this.mode.dev) {
				ctx.auth = openCapabilityContext()
				return next()
			}
			const result = await new PropustkaAuth(this.mode.binding, this.appId, { issuer: this.mode.issuer, gates: { rules: [] } }).redeemKey(token)
			if (!result.ok) {
				return notFound()
			}
			ctx.auth = result.context
			return next()
		}
	}

	/**
	 * The standard dev persona-switch handler: set the persona cookie from `?as=<email>` and 302 to `/`,
	 * so apps drop their bespoke `/__dev/login`. Gate it behind dev in your router (it always sets the
	 * cookie; it does not check the mode itself).
	 */
	devLoginHandler(): (request: Request) => Response {
		const cookieName = this.devPersonaCookie
		return (request) => {
			const as = new URL(request.url).searchParams.get('as') ?? ''
			const headers = new Headers({ location: '/' })
			headers.append('set-cookie', `${cookieName}=${encodeURIComponent(as)}; Path=/; SameSite=Lax`)
			return new Response(null, { status: 302, headers })
		}
	}

	// ── Internals ─────────────────────────────────────────────────────────────────

	/** Resolve a dev persona to a `SessionAuthResult` (so success/failure flow through the same path). */
	private resolveDevPersona(request: Request): SessionAuthResult {
		// `__as` is decoded by URLSearchParams; the cookie was URL-encoded by `devLoginHandler`, so decode it.
		const cookieSelector = readCookie(request.headers.get('Cookie'), this.devPersonaCookie)
		const selector = new URL(request.url).searchParams.get('__as') ?? (cookieSelector === null ? null : safeDecode(cookieSelector))
			?? this.devDefaultPersona
			?? null
		if (selector === null) {
			return { ok: false, reason: 'no_session', status: 401 }
		}
		const persona = this.devPersonas?.[selector]
		if (persona === undefined) {
			return { ok: false, reason: 'unknown_principal', status: 403 }
		}
		return { ok: true, context: makeDevContext(persona) }
	}
}

// ── createIam ──────────────────────────────────────────────────────────────────

/**
 * The single request-time entry point. Reads `env.IAM` / `env.PROPUSTKA_URL` / `env.DEV` and the app id
 * (`opts.appId` ?? `env.PROPUSTKA_APP_ID`), and returns an `Iam` backed by the fake (dev) or the real
 * binding (off-local). Throws if the app id is missing, or — off-local — if the binding or issuer is.
 */
export function createIam(env: IamEnv, opts: CreateIamOptions = {}): Iam {
	const appId = opts.appId ?? env.PROPUSTKA_APP_ID
	if (appId === undefined || appId === '') {
		throw new Error('createIam: app id is required — pass opts.appId or set env.PROPUSTKA_APP_ID')
	}
	const devPersonaCookie = opts.devPersonaCookie ?? 'propustka_dev_principal'

	if (env.DEV) {
		const fakePersonas = toFakePersonas(opts.devPersonas)
		const management = new FakeIamClient(fakePersonas === undefined ? {} : { personas: fakePersonas })
		return new Iam({
			management,
			mode: { dev: true },
			appId,
			devPersonas: opts.devPersonas,
			devDefaultPersona: opts.devDefaultPersona,
			devPersonaCookie,
		})
	}

	const binding = env.IAM
	if (binding === undefined) {
		throw new Error('createIam: the IAM service binding is missing off-local (env.IAM) — check the propustka ServiceReference.')
	}
	const issuer = env.PROPUSTKA_URL
	if (issuer === undefined || issuer === '') {
		throw new Error('createIam: PROPUSTKA_URL is missing off-local — required as the PropustkaAuth issuer (propustka origin).')
	}
	const management = new IamClient(binding, appId)
	return new Iam({
		management,
		mode: { dev: false, binding, issuer },
		appId,
		devPersonas: opts.devPersonas,
		devDefaultPersona: opts.devDefaultPersona,
		devPersonaCookie,
	})
}
