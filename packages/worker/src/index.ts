import type {
	AuditInput,
	IamRpc,
	IssueJwtInput,
	IssueJwtResult,
	IssueKeyInput,
	IssueKeyResult,
	Jwks,
	ListPrincipalsInput,
	ListPrincipalsResult,
	MintFromKeyInput,
	MintFromKeyResult,
	MintTokenInput,
	MintTokenResult,
	PrincipalListItem,
	RevokeKeyInput,
	RevokeKeyResult,
} from '@propustka/core'
import { WorkerEntrypoint } from 'cloudflare:workers'
import { handleAdmin } from './admin/router'
import { resolveCaller } from './auth'
import { handleAuth } from './auth/routes'
import type { Env } from './env'
import { issueJwt, issueKey, revokeKey } from './issue'
import { buildServices } from './services'
import { getSigner } from './signing'
import { mintFromKey, mintToken } from './tokens'

// Retention: prune `auth_log` rows older than this on the daily cron. `audit_events`
// are kept long; only the dense, high-churn auth log is pruned.
const AUTH_LOG_RETENTION_SECONDS = 30 * 24 * 60 * 60 // 30 days

/**
 * The IAM Worker. A single `WorkerEntrypoint` whose default export carries BOTH the
 * RPC methods (apps reach them over the `env.IAM` service binding — which does not
 * traverse the Access edge) and `fetch()` (the admin SPA + `/admin/*`, behind
 * Access). It exposes no public HTTP.
 *
 * SECURITY MODEL: the management RPCs (`issueKey`/`issueJwt`/`revokeKey`/`listPrincipals`) resolve
 * the CALLER server-side from a forwarded propustka-native credential (`resolveCaller` — a `px_token`
 * verified against our own signing keys, or a `px_` key), never app-asserted. On a valid `px_token`
 * the credential's `aud` identifies the app and supersedes the SDK-passed `app` for the audit row.
 */
export class Propustka extends WorkerEntrypoint<Env> implements IamRpc {
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

	/**
	 * Mint a per-app access token from an opaque `px_` credential (API key / share link) — the other
	 * front over the same resolve→sign core as `mintToken`. Validates the credential, resolves its
	 * effective permissions, signs a short-lived token. Never throws — fails closed to `invalid_key`.
	 */
	async mintFromKey(input: MintFromKeyInput): Promise<MintFromKeyResult> {
		const services = buildServices(this.env)
		try {
			const { result, principalId, credentialId } = await mintFromKey(services, this.env, input)
			this.ctx.waitUntil(
				services.db.writeAuthLog({
					requestId: input.requestId,
					app: input.app,
					kind: 'authenticate',
					principalId,
					credentialId,
					decision: result.ok ? 'allow' : 'deny',
					reason: result.ok ? 'mint_key' : result.reason,
				}),
			)
			return result
		} catch (err) {
			// Same fail-closed posture as mintToken(): never surface a 500.
			console.error(`mintFromKey failed for request '${input.requestId}'`, err)
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
			return { ok: false, reason: 'invalid_key' }
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
					credentialId: event.credentialId ?? null,
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
			// Resolve the CALLER from the forwarded native credential — never a self-asserted principal.
			// The app we list is the credential's verified app, so an operator only ever enumerates the
			// roster of an app it holds a token for.
			const res = await resolveCaller(services, this.env, { app: input.app, credential: input.credential, requestId: input.requestId })
			if (!res.ok) {
				return { ok: false, reason: res.reason }
			}
			// Authorize: a real principal-bound MEMBER holding ≥1 permission on the app. An anonymous
			// credential (a passthrough JWT) and a zero-grant user cannot enumerate the roster.
			if (res.caller.type === undefined || res.caller.permissions.length === 0) {
				return { ok: false, reason: 'not_allowed' }
			}
			const rows = await services.db.getPrincipalsForApp(res.verifiedApp)
			const principals: PrincipalListItem[] = rows.map((p) => ({
				id: p.id,
				type: p.type,
				label: p.label,
				email: p.email,
				disabled: p.disabled_at !== null,
			}))
			return { ok: true, principals }
		} catch (err) {
			// Fail closed — never surface a 500. A read needs no auth_log row.
			console.error(`listPrincipals failed for request '${input.requestId}'`, err)
			return { ok: false, reason: 'unknown_principal' }
		}
	}

	async revokeKey(input: RevokeKeyInput): Promise<RevokeKeyResult> {
		const services = buildServices(this.env)
		try {
			// Resolve + authorize the REVOKER from the forwarded native credential — like the issue path.
			const res = await resolveCaller(services, this.env, { app: input.app, credential: input.credential, requestId: input.requestId })
			if (!res.ok) {
				return { ok: false, reason: res.reason }
			}
			if (res.caller.type === undefined) {
				// An anonymous credential cannot revoke — there is no accountable principal.
				return { ok: false, reason: 'not_allowed' }
			}
			const revoker = res.caller

			const result = await revokeKey(services, input, { id: revoker.id, permissions: revoker.permissions })

			// Audit only an actual state change (revoked === true); a no-op idempotent
			// revoke or a denied/not-found attempt writes no domain event.
			if (result.ok && result.revoked) {
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: revoker.id,
						principalLabel: revoker.label ?? revoker.id,
						app: res.verifiedApp,
						action: 'iam.credential.revoke',
						resourceType: 'credential',
						resourceId: input.id,
					}),
				)
			}

			return result
		} catch (err) {
			console.error(`revokeKey failed for request '${input.requestId}'`, err)
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

	async issueKey(input: IssueKeyInput): Promise<IssueKeyResult> {
		const services = buildServices(this.env)
		try {
			// Resolve the ISSUER from the forwarded native credential.
			const res = await resolveCaller(services, this.env, { app: input.app, credential: input.credential, requestId: input.requestId })
			if (!res.ok) {
				return { ok: false, reason: res.reason }
			}
			if (res.caller.type === undefined) {
				// An anonymous credential cannot issue — delegation + audit require an accountable principal.
				return { ok: false, reason: 'not_allowed' }
			}
			const issuer = res.caller
			const app = res.verifiedApp
			const { result, auditLabel } = await issueKey(services, input, { id: issuer.id, permissions: issuer.permissions }, app)

			if (result.ok) {
				// iam.credential.create audit — issuer, label, binding + grants; NEVER the plaintext token.
				// `result.principalId` is the freshly-created service principal (service mode) or the
				// self-bound principal; falls back to the requested binding for the standalone modes.
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: issuer.id,
						principalLabel: issuer.label ?? issuer.id,
						app,
						action: 'iam.credential.create',
						resourceType: 'credential',
						resourceId: result.id,
						metadata: {
							label: auditLabel ?? null,
							principalId: result.principalId ?? input.principalId ?? null,
							service: input.service !== undefined,
							grants: input.service?.permissions ?? input.permissions ?? [],
						},
					}),
				)
			}

			return result
		} catch (err) {
			console.error(`issueKey failed for request '${input.requestId}'`, err)
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

	async issueJwt(input: IssueJwtInput): Promise<IssueJwtResult> {
		const services = buildServices(this.env)
		try {
			const res = await resolveCaller(services, this.env, { app: input.app, credential: input.credential, requestId: input.requestId })
			if (!res.ok) {
				return { ok: false, reason: res.reason }
			}
			if (res.caller.type === undefined) {
				return { ok: false, reason: 'not_allowed' }
			}
			const issuer = res.caller
			const app = res.verifiedApp
			const { result, auditLabel } = await issueJwt(services, this.env, input, { id: issuer.id, permissions: issuer.permissions })

			if (result.ok) {
				// iam.passthrough.issue audit — issuer, label, grants, expiry; NEVER the signed token.
				this.ctx.waitUntil(
					services.db.writeAuditEvent({
						requestId: input.requestId,
						principalId: issuer.id,
						principalLabel: issuer.label ?? issuer.id,
						app,
						action: 'iam.passthrough.issue',
						resourceType: 'token',
						resourceId: result.id,
						metadata: { label: auditLabel ?? null, grants: input.permissions, expiresAt: result.expiresAt },
					}),
				)
			}

			return result
		} catch (err) {
			console.error(`issueJwt failed for request '${input.requestId}'`, err)
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
