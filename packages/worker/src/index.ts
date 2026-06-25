import type {
	AuditInput,
	AuthenticateInput,
	AuthenticateResult,
	IamRpc,
	IssueCapabilityInput,
	IssueCapabilityResult,
	IssueServiceTokenInput,
	IssueServiceTokenResult,
	Jwks,
	ListPrincipalsInput,
	ListPrincipalsResult,
	MintTokenInput,
	MintTokenResult,
	PrincipalListItem,
	RedeemCapabilityInput,
	RedeemCapabilityResult,
	RevokeCapabilityInput,
	RevokeCapabilityResult,
	RevokeServiceTokenInput,
	RevokeServiceTokenResult,
	RotateServiceTokenInput,
	RotateServiceTokenResult,
} from '@propustka/core'
import { WorkerEntrypoint } from 'cloudflare:workers'
import { handleAdmin } from './admin/router'
import { principalFromOutcome, resolveRequest } from './auth'
import { handleAuth } from './auth/routes'
import { issueCapability, redeemCapability, revokeCapability } from './capabilities'
import type { Env } from './env'
import { buildServices } from './services'
import { issueServiceToken, revokeServiceToken, rotateServiceToken } from './servicetokens'
import { getSigner } from './signing'
import { mintToken } from './tokens'

// Retention: prune `auth_log` rows older than this on the daily cron. `audit_events`
// are kept long; only the dense, high-churn auth log is pruned.
const AUTH_LOG_RETENTION_SECONDS = 30 * 24 * 60 * 60 // 30 days

/**
 * The IAM Worker. A single `WorkerEntrypoint` whose default export carries BOTH the
 * RPC methods (apps reach them over the `env.IAM` service binding — which does not
 * traverse the Access edge) and `fetch()` (the admin SPA + `/admin/*`, behind
 * Access). It exposes no public HTTP.
 *
 * SECURITY MODEL (hard requirement 3): on calls that forward a valid Access JWT
 * (`authenticate`, `issueCapability`), the verified `aud` identifies the app and
 * supersedes the SDK-passed `app` for the auth log / context. The SDK-passed app is
 * trusted only where no token exists (`audit`, `redeemCapability`, failure-path log
 * rows) — for labeling, not as a security boundary. Principal identity is always
 * resolved server-side from the forwarded credentials, never app-asserted.
 */
export class Propustka extends WorkerEntrypoint<Env> implements IamRpc {
	async authenticate(input: AuthenticateInput): Promise<AuthenticateResult> {
		const services = buildServices(this.env)
		try {
			const outcome = await resolveRequest(services, input)

			// One auth_log row per call, fire-and-forget (never delays/fails the user op).
			// The app column is the verified aud-derived id on success, the self-asserted
			// id on failure paths (no valid token there).
			const app = outcome.verifiedApp ?? input.app
			const resolved = principalFromOutcome(outcome)
			const reason = outcome.result.ok
				? (outcome.logReason ?? undefined)
				: (outcome.logReason ?? outcome.result.reason)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app,
					kind: 'authenticate',
					principalId: resolved?.id ?? null,
					decision: outcome.result.ok ? 'allow' : 'deny',
					reason: reason ?? null,
				}),
			)

			// Log an SDK/aud app mismatch — a misconfigured SDK constructor, not an attack.
			if (outcome.verifiedApp && outcome.verifiedApp !== input.app) {
				console.warn(`app mismatch: sdk='${input.app}' aud='${outcome.verifiedApp}' request='${input.requestId}'`)
			}

			return outcome.result
		} catch (err) {
			// resolveRequest is documented as never-throws, but a transient D1 error can still
			// propagate. Fail closed: never surface a 500. Record a deny auth_log row (the precise
			// 'internal_error' lives only in the free-string reason column — the AuthenticateResult
			// reason union has no such variant and must not gain one) and return unknown_principal
			// (maps to 403). No happy-path row was written on this path, so there's no double-write.
			console.error(`authenticate failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	/**
	 * Mint a per-app permission token from the browser's SSO session (propustka-native auth). The
	 * session is validated, the principal's permissions for the calling app resolved, and a
	 * short-lived token signed; the SDK then authorizes locally off it until it expires. Never
	 * throws — fails closed to `invalid_session` (the SDK then bounces the user to /auth/login).
	 */
	async mintToken(input: MintTokenInput): Promise<MintTokenResult> {
		const services = buildServices(this.env)
		try {
			const { result, principalId } = await mintToken(services, this.env, input)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId,
					decision: result.ok ? 'allow' : 'deny',
					reason: result.ok ? 'mint' : result.reason,
				}),
			)
			return result
		} catch (err) {
			// Same fail-closed posture as authenticate(): never surface a 500.
			console.error(`mintToken failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'invalid_session' }
		}
	}

	/** The public signing key set — fetched once per isolate by the SDK to verify tokens locally. */
	async getJwks(): Promise<Jwks> {
		const signer = await getSigner(this.env)
		return signer.jwks()
	}

	/**
	 * Fire-and-forget domain audit write. Returns void and NEVER throws to the
	 * caller — a failed audit write must not fail or delay the user-facing op. The
	 * `app` here is self-asserted (no token on this call); audit labeling only.
	 */
	async audit(event: AuditInput): Promise<void> {
		const services = buildServices(this.env)
		this.ctx.waitUntil(
			services.db
				.writeAuditEvent({
					requestId: event.requestId,
					principalId: event.principalId,
					principalLabel: event.principalLabel,
					capabilityTokenId: event.capabilityTokenId ?? null,
					app: event.app,
					action: event.action,
					resourceType: event.resourceType,
					resourceId: event.resourceId ?? null,
					diff: event.diff,
					metadata: event.metadata,
				})
				.catch((err: unknown) => {
					console.error('audit write failed', err)
				}),
		)
	}

	async listPrincipals(input: ListPrincipalsInput): Promise<ListPrincipalsResult> {
		const services = buildServices(this.env)
		try {
			// Resolve the CALLER from the forwarded credentials, exactly like authenticate() —
			// never a self-asserted principal. The app we list is the aud-VERIFIED app, so an
			// operator can only ever enumerate the roster of an app it authenticates to.
			const outcome = await resolveRequest(services, {
				app: input.app,
				token: input.token,
				cookie: input.cookie,
				origin: input.origin,
				requestId: input.requestId,
			})
			const caller = principalFromOutcome(outcome)
			if (!caller || !outcome.result.ok) {
				return outcome.result.ok ? { ok: false, reason: 'unknown_principal' } : { ok: false, reason: outcome.result.reason }
			}
			// Authorize: the caller must be a real MEMBER of the app — hold at least one permission
			// on the verified app. A zero-grant lazy-created user (authenticated but ungranted) and
			// the app-less local-dev bypass (verifiedApp === null) cannot enumerate the roster.
			const app = outcome.verifiedApp
			if (app === null || caller.permissions.length === 0) {
				return { ok: false, reason: 'not_allowed' }
			}
			const rows = await services.db.getPrincipalsForApp(app)
			const principals: PrincipalListItem[] = rows.map((p) => ({
				id: p.id,
				type: p.type,
				label: p.label,
				email: p.email,
				disabled: p.disabled_at !== null,
			}))
			return { ok: true, principals }
		} catch (err) {
			// Same fail-closed posture as authenticate(): never surface a 500. A read needs no
			// auth_log row (the auth_log `kind` union has only authenticate/redeem); fail closed.
			console.error(`listPrincipals failed for request '${input.requestId}'`, err)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	async redeemCapability(input: RedeemCapabilityInput): Promise<RedeemCapabilityResult> {
		const services = buildServices(this.env)
		const result = await redeemCapability(services, input)

		// auth_log row: kind='redeem', principal_id NULL, capability_token_id set on
		// success. The app is self-asserted (no token on a redeem). Fire-and-forget.
		this.ctx.waitUntil(
			services.db.writeAuthLog({
				requestId: input.requestId,
				app: input.app,
				kind: 'redeem',
				principalId: null,
				capabilityTokenId: result.ok ? result.tokenId : null,
				decision: result.ok ? 'allow' : 'deny',
				reason: result.ok ? null : result.reason,
			}),
		)

		return result
	}

	async issueCapability(input: IssueCapabilityInput): Promise<IssueCapabilityResult> {
		const services = buildServices(this.env)
		try {
			// Resolve the ISSUER from the forwarded credentials exactly like authenticate()
			// — never a self-asserted principal id (same failure reasons).
			const outcome = await resolveRequest(services, {
				app: input.app,
				token: input.token,
				cookie: input.cookie,
				origin: input.origin,
				requestId: input.requestId,
			})
			const issuer = principalFromOutcome(outcome)
			if (!issuer || !outcome.result.ok) {
				// Map the auth failure straight through (missing/invalid/unknown/disabled).
				return outcome.result.ok ? { ok: false, reason: 'unknown_principal' } : { ok: false, reason: outcome.result.reason }
			}

			const { result, auditLabel } = await issueCapability(services, input, issuer)

			if (result.ok) {
				// iam.capability.create audit event — issuer, label, grants; NEVER plaintext.
				const app = outcome.verifiedApp ?? input.app
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: issuer.id,
						principalLabel: outcome.result.principal.label,
						app,
						action: 'iam.capability.create',
						resourceType: 'capability',
						resourceId: result.id,
						metadata: {
							label: auditLabel ?? null,
							grants: input.grants.map((g) => ({ action: g.action, resource: g.resource })),
						},
					}),
				)
			}

			return result
		} catch (err) {
			// Same fail-closed posture as authenticate(): never surface a 500. Record a deny
			// auth_log row for the issuer-resolution path ('internal_error' goes only into the
			// free-string reason column — the IssueCapabilityResult union has no such variant and
			// must not gain one) and return unknown_principal (maps to 403).
			console.error(`issueCapability failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	async revokeCapability(input: RevokeCapabilityInput): Promise<RevokeCapabilityResult> {
		const services = buildServices(this.env)
		try {
			// Resolve + authorize the REVOKER from the forwarded credentials, exactly like
			// issueCapability resolves the issuer — never a self-asserted principal id.
			const outcome = await resolveRequest(services, {
				app: input.app,
				token: input.token,
				cookie: input.cookie,
				origin: input.origin,
				requestId: input.requestId,
			})
			const revoker = principalFromOutcome(outcome)
			if (!revoker || !outcome.result.ok) {
				return outcome.result.ok ? { ok: false, reason: 'unknown_principal' } : { ok: false, reason: outcome.result.reason }
			}

			const result = await revokeCapability(services, input, revoker)

			// Audit only an actual state change (revoked === true); a no-op idempotent
			// revoke or a denied/not-found attempt writes no domain event.
			if (result.ok && result.revoked) {
				const app = outcome.verifiedApp ?? input.app
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: revoker.id,
						principalLabel: outcome.result.principal.label,
						app,
						action: 'iam.capability.revoke',
						resourceType: 'capability',
						resourceId: input.tokenId,
					}),
				)
			}

			return result
		} catch (err) {
			// Same fail-closed posture as authenticate()/issueCapability(): never surface a 500.
			console.error(`revokeCapability failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	async issueServiceToken(input: IssueServiceTokenInput): Promise<IssueServiceTokenResult> {
		const services = buildServices(this.env)
		try {
			// Resolve the ISSUER from the forwarded credentials exactly like issueCapability().
			const outcome = await resolveRequest(services, {
				app: input.app,
				token: input.token,
				cookie: input.cookie,
				origin: input.origin,
				requestId: input.requestId,
			})
			const issuer = principalFromOutcome(outcome)
			if (!issuer || !outcome.result.ok) {
				return outcome.result.ok ? { ok: false, reason: 'unknown_principal' } : { ok: false, reason: outcome.result.reason }
			}

			const app = outcome.verifiedApp ?? input.app
			const result = await issueServiceToken(
				services,
				input,
				{ id: issuer.id, label: outcome.result.principal.label, permissions: issuer.permissions },
				app,
			)

			if (result.ok) {
				// iam.servicetoken.create audit — issuer, label, granted actions + scope; NEVER the secret.
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: issuer.id,
						principalLabel: outcome.result.principal.label,
						app,
						action: 'iam.servicetoken.create',
						resourceType: 'principal',
						resourceId: result.principalId,
						metadata: {
							label: input.label,
							permissions: input.permissions,
							scope: input.scope ?? null,
							clientId: result.clientId,
						},
					}),
				)
			}

			return result
		} catch (err) {
			console.error(`issueServiceToken failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	async revokeServiceToken(input: RevokeServiceTokenInput): Promise<RevokeServiceTokenResult> {
		const services = buildServices(this.env)
		try {
			const outcome = await resolveRequest(services, {
				app: input.app,
				token: input.token,
				cookie: input.cookie,
				origin: input.origin,
				requestId: input.requestId,
			})
			const revoker = principalFromOutcome(outcome)
			if (!revoker || !outcome.result.ok) {
				return outcome.result.ok ? { ok: false, reason: 'unknown_principal' } : { ok: false, reason: outcome.result.reason }
			}

			const app = outcome.verifiedApp ?? input.app
			const result = await revokeServiceToken(services, input, {
				id: revoker.id,
				label: outcome.result.principal.label,
				permissions: revoker.permissions,
			}, app)

			if (result.ok && result.revoked) {
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: revoker.id,
						principalLabel: outcome.result.principal.label,
						app,
						action: 'iam.servicetoken.revoke',
						resourceType: 'principal',
						resourceId: input.principalId,
					}),
				)
			}

			return result
		} catch (err) {
			console.error(`revokeServiceToken failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	async rotateServiceToken(input: RotateServiceTokenInput): Promise<RotateServiceTokenResult> {
		const services = buildServices(this.env)
		try {
			const outcome = await resolveRequest(services, {
				app: input.app,
				token: input.token,
				cookie: input.cookie,
				origin: input.origin,
				requestId: input.requestId,
			})
			const caller = principalFromOutcome(outcome)
			if (!caller || !outcome.result.ok) {
				return outcome.result.ok ? { ok: false, reason: 'unknown_principal' } : { ok: false, reason: outcome.result.reason }
			}

			const app = outcome.verifiedApp ?? input.app
			const result = await rotateServiceToken(
				services,
				input,
				{ id: caller.id, label: outcome.result.principal.label, permissions: caller.permissions },
				app,
			)

			if (result.ok) {
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: caller.id,
						principalLabel: outcome.result.principal.label,
						app,
						action: 'iam.servicetoken.rotate',
						resourceType: 'principal',
						resourceId: input.principalId,
						metadata: { clientId: result.clientId },
					}),
				)
			}

			return result
		} catch (err) {
			console.error(`rotateServiceToken failed for request '${input.requestId}'`, err)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId: null,
					decision: 'deny',
					reason: 'internal_error',
				}),
			)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	/**
	 * HTTP surface: any `/admin/*` path → the admin JSON router (which re-checks
	 * admin rights in-Worker); everything else → the admin SPA assets. Both are
	 * behind Access (the admin policy) at the edge.
	 */
	override async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url)
		// propustka-native auth: public (no Access gate) — login/callback/logout + the JWKS.
		if (url.pathname === '/.well-known/jwks.json' || url.pathname === '/auth' || url.pathname.startsWith('/auth/')) {
			const services = buildServices(this.env)
			return handleAuth(request, services, this.env, this.ctx)
		}
		if (url.pathname === '/admin' || url.pathname.startsWith('/admin/')) {
			const services = buildServices(this.env)
			return handleAdmin(request, services, this.ctx)
		}
		return this.env.ASSETS.fetch(request)
	}

	/**
	 * Daily cron (see triggers.crons): prune old `auth_log` rows (retention: weeks).
	 * `WorkerEntrypoint.scheduled` receives only the controller; `env`/`ctx` come
	 * from `this`.
	 */
	override async scheduled(_controller: ScheduledController): Promise<void> {
		const services = buildServices(this.env)
		const cutoff = Math.floor(Date.now() / 1000) - AUTH_LOG_RETENTION_SECONDS
		this.ctx.waitUntil(services.db.pruneAuthLog(cutoff).then(() => undefined))
	}
}

export default Propustka
