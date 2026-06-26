import { API_KEY_PREFIX, type PermissionEntry, type PrincipalType } from '@propustka/core'
import type { Env } from './env'
import { hashToken } from './secret'
import type { Services } from './services'
import { getSigner, verifyAccessToken } from './signing'
import { resolveCredential } from './tokens'

/**
 * Fixed identity for the local dev bypass below. A row with this id is seeded into
 * `principals` (see `seed.dev.sql`) so audit/auth-log foreign keys resolve.
 */
export const LOCAL_DEV_ADMIN_ID = 'local-dev-admin'

// ── Native caller resolution (propustka-native credentials, no Cloudflare Access) ──────────────
//
// Resolve the CALLER for the management RPCs (`issueKey`/`issueJwt`/`revokeKey`/`listPrincipals`)
// and the admin gate from a propustka-native credential the SDK forwards — a `px_token` access JWT
// (verified against our OWN signing keys) or an opaque `px_` key (resolved via the same
// `resolveCredential` core as `mintFromKey`). There is no Cloudflare Access JWT anymore.

/** The resolved caller. `type` is absent for an ANONYMOUS credential (a passthrough JWT / share link). */
export interface ResolvedCaller {
	id: string
	type?: PrincipalType
	label: string | null
	permissions: PermissionEntry[]
}

export type CallerResolution =
	| { ok: true; caller: ResolvedCaller; verifiedApp: string }
	| { ok: false; reason: 'missing_token' | 'invalid_token' | 'unknown_principal' | 'disabled' }

export async function resolveCaller(
	services: Services,
	env: Pick<Env, 'PROPUSTKA_SIGNING_KEYS' | 'ENVIRONMENT'>,
	input: { app: string; credential: string | null; requestId: string },
): Promise<CallerResolution> {
	// LOCAL DEV BYPASS. With NO durable signing keys configured (an ephemeral key ⇒ dev-only) AND no
	// credential presented, resolve a fixed global-admin so the example app / admin scripts work
	// against `lopata`/`wrangler dev`. A real deploy provisions PROPUSTKA_SIGNING_KEYS, so this branch
	// is impossible there.
	if (services.config.environment === 'local' && input.credential === null && (env.PROPUSTKA_SIGNING_KEYS ?? '').trim() === '') {
		console.warn('local dev bypass active: resolving fixed global-admin caller (ENVIRONMENT=local, no signing keys configured)')
		return {
			ok: true,
			caller: { id: LOCAL_DEV_ADMIN_ID, type: 'user', label: 'local-dev-admin', permissions: [{ action: '*', scope: null, source: 'bootstrap' }] },
			verifiedApp: input.app,
		}
	}

	if (input.credential === null) {
		return { ok: false, reason: 'missing_token' }
	}

	// An opaque `px_` key → resolve its effective permissions (the same 2×2 as mintFromKey).
	if (input.credential.startsWith(API_KEY_PREFIX)) {
		const cred = await services.db.getActiveCredentialByHash(await hashToken(input.credential))
		if (!cred) {
			return { ok: false, reason: 'invalid_token' }
		}
		const eff = await resolveCredential(services, cred, input.app)
		if (!eff.ok) {
			return { ok: false, reason: eff.reason }
		}
		return {
			ok: true,
			caller: { id: eff.subject, ...(eff.type === undefined ? {} : { type: eff.type }), label: eff.label, permissions: eff.permissions },
			verifiedApp: input.app,
		}
	}

	// A `px_token` access JWT → verify against OUR OWN signing keys; `aud` IS the app id and `perms`
	// ARE the caller's resolved permissions for that app (the same snapshot the SDK's `can()` trusts).
	const signer = await getSigner(env)
	const claims = await verifyAccessToken(signer, input.credential, { issuer: services.config.issuer, audience: input.app })
	if (!claims) {
		return { ok: false, reason: 'invalid_token' }
	}
	return {
		ok: true,
		caller: { id: claims.sub, ...(claims.ptype === undefined ? {} : { type: claims.ptype }), label: claims.label, permissions: claims.perms },
		verifiedApp: claims.aud,
	}
}
