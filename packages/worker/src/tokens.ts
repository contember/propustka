/**
 * Minting per-app permission tokens from an SSO session — the heart of propustka-native auth.
 *
 * `mintToken` is the ONE place a session becomes authorization: validate the opaque session cookie,
 * resolve the principal's permissions for the calling app (the same `resolveUserPermissions` the
 * legacy `authenticate()` uses — grants ∪ bootstrap; groups don't apply without Cloudflare Access
 * get-identity), and sign a short-lived `principal` token. The SDK then authorizes locally off that
 * token until it expires, so this runs ≈ once per TTL per app, not per request.
 */

import { buildAccessClaims, DEFAULT_TOKEN_TTL_SECONDS, type MintTokenInput, type MintTokenResult } from '@propustka/core'
import { hashToken } from './capabilities'
import { principalStatus } from './db'
import type { Env } from './env'
import { resolveUserPermissions } from './resolve'
import type { Services } from './services'
import { getSigner } from './signing'

/** The env slice mint needs (the signing keys + environment for `getSigner`). */
type MintEnv = Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>

/** `principalId` (resolved session subject, or null on failure) is surfaced for the auth_log row. */
export interface MintOutcome {
	result: MintTokenResult
	principalId: string | null
}

export async function mintToken(services: Services, env: MintEnv, input: MintTokenInput): Promise<MintOutcome> {
	if (!input.session) {
		return { result: { ok: false, reason: 'no_session' }, principalId: null }
	}

	const session = await services.db.getActiveSessionByHash(await hashToken(input.session))
	if (!session) {
		return { result: { ok: false, reason: 'invalid_session' }, principalId: null }
	}

	const principal = await services.db.getPrincipalById(session.principal_id)
	if (!principal) {
		// The session outlived its principal (deleted) — treat as unknown.
		return { result: { ok: false, reason: 'unknown_principal' }, principalId: null }
	}
	if (principalStatus(principal) === 'disabled') {
		return { result: { ok: false, reason: 'disabled' }, principalId: principal.id }
	}

	// Resolve permissions for the requesting app. Sessions are a USER credential (Google login);
	// no get-identity cookie/origin in the propustka-native world, so groups don't contribute.
	const { permissions } = await resolveUserPermissions({
		db: services.db,
		identity: services.identity,
		principal,
		cookie: null,
		origin: null,
		bootstrapAdmins: services.config.bootstrapAdmins,
		app: input.app,
	})

	const signer = await getSigner(env)
	const now = Math.floor(Date.now() / 1000)
	const expiresAt = now + DEFAULT_TOKEN_TTL_SECONDS
	const token = await signer.sign(
		buildAccessClaims({
			iss: services.config.issuer,
			app: input.app,
			subject: principal.id,
			type: principal.type,
			label: principal.label,
			permissions,
			issuedAt: now,
			expiresAt,
		}),
	)
	return { result: { ok: true, token, expiresAt }, principalId: principal.id }
}
