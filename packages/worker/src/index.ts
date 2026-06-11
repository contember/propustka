import type {
	AuditInput,
	AuthenticateInput,
	AuthenticateResult,
	IamRpc,
	IssueCapabilityInput,
	IssueCapabilityResult,
	RedeemCapabilityInput,
	RedeemCapabilityResult,
	RevokeCapabilityInput,
	RevokeCapabilityResult,
} from '@propustka/core'
import { WorkerEntrypoint } from 'cloudflare:workers'
import { handleAdmin } from './admin/router'
import { principalFromOutcome, resolveRequest } from './auth'
import { issueCapability, redeemCapability, revokeCapability } from './capabilities'
import type { Env } from './env'
import { buildServices } from './services'

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

	/**
	 * HTTP surface: any `/admin/*` path → the admin JSON router (which re-checks
	 * admin rights in-Worker); everything else → the admin SPA assets. Both are
	 * behind Access (the admin policy) at the edge.
	 */
	override async fetch(request: Request): Promise<Response> {
		const url = new URL(request.url)
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
