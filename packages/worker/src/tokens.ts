/**
 * Minting per-app access tokens — the heart of propustka-native auth.
 *
 * Two fronts over one resolve→sign core (see `propustka-native-spec.md`):
 *   - `mintToken`   — from the browser's opaque SSO session cookie (a principal-bound credential in a
 *     cookie). Validates the session, resolves the principal's permissions for the calling app.
 *   - `mintFromKey` — from an opaque `px_` credential (API key / share link) presented as a bearer or
 *     URL-path token. Resolves the credential's EFFECTIVE permissions (the 2×2: principal? ∩ inline).
 *
 * Both end in `signAccessToken`: sign a short-lived token the SDK then verifies locally, so this runs
 * ≈ once per TTL per app, not per request. `mintToken` always yields a principal token; `mintFromKey`
 * yields a principal token (bound credential) or an anonymous one (frozen inline grants).
 */

import {
	type AccessTokenClaims,
	buildAccessClaims,
	DEFAULT_TOKEN_TTL_SECONDS,
	type MintFromKeyResult,
	type MintTokenInput,
	type MintTokenResult,
	type PermissionEntry,
	permits,
	type PrincipalType,
	type Scope,
} from '@propustka/core'
import { hashToken } from './capabilities'
import type { CredentialGrantRow, CredentialRow } from './db'
import { principalStatus } from './db'
import type { Env } from './env'
import { resolveServicePermissions, resolveUserPermissions } from './resolve'
import type { Services } from './services'
import { getSigner } from './signing'

/** The env slice minting needs (the signing keys + environment for `getSigner`). */
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

	// Resolve permissions for the requesting app. Sessions are a USER credential (OIDC login); no
	// get-identity cookie/origin in the propustka-native world, so groups don't contribute.
	const { permissions } = await resolveUserPermissions({
		db: services.db,
		identity: services.identity,
		principal,
		cookie: null,
		origin: null,
		bootstrapAdmins: services.config.bootstrapAdmins,
		app: input.app,
	})

	const now = Math.floor(Date.now() / 1000)
	const expiresAt = now + DEFAULT_TOKEN_TTL_SECONDS
	const token = await signAccessToken(services, env, {
		app: input.app,
		subject: principal.id,
		type: principal.type,
		label: principal.label,
		permissions,
		issuedAt: now,
		expiresAt,
	})
	return { result: { ok: true, token, expiresAt }, principalId: principal.id }
}

/** `principalId`/`credentialId` are surfaced for the auth_log row. */
export interface MintFromKeyOutcome {
	result: MintFromKeyResult
	principalId: string | null
	credentialId: string | null
}

/**
 * Resolve an opaque `px_` credential into an access token. The credential's EFFECTIVE permissions
 * follow the 2×2: principal-bound → that principal's live resolved perms (∩ inline restriction when
 * present); anonymous → its frozen inline grants. The signed token is principal-bound (carries
 * `ptype`) iff the credential is.
 */
export async function mintFromKey(
	services: Services,
	env: MintEnv,
	input: { app: string; key: string; requestId: string },
): Promise<MintFromKeyOutcome> {
	const cred = await services.db.getActiveCredentialByHash(await hashToken(input.key))
	if (!cred) {
		return { result: { ok: false, reason: 'invalid_key' }, principalId: null, credentialId: null }
	}

	const effective = await resolveCredential(services, cred, input.app)
	if (!effective.ok) {
		return { result: { ok: false, reason: effective.reason }, principalId: cred.principal_id, credentialId: cred.id }
	}

	const now = Math.floor(Date.now() / 1000)
	const expiresAt = Math.min(now + DEFAULT_TOKEN_TTL_SECONDS, cred.expires_at ?? Number.POSITIVE_INFINITY)
	const token = await signAccessToken(services, env, {
		app: input.app,
		subject: effective.subject,
		...(effective.type === undefined ? {} : { type: effective.type }),
		label: effective.label,
		permissions: effective.permissions,
		issuedAt: now,
		expiresAt,
	})
	return { result: { ok: true, token, expiresAt }, principalId: cred.principal_id, credentialId: cred.id }
}

/** The credential's effective permissions + the token subject/type/label, or a typed failure. */
type ResolvedCredential =
	| { ok: true; subject: string; type?: PrincipalType; label: string | null; permissions: PermissionEntry[] }
	| { ok: false; reason: 'unknown_principal' | 'disabled' }

async function resolveCredential(services: Services, cred: CredentialRow, app: string): Promise<ResolvedCredential> {
	const inline = (await services.db.getCredentialGrants(cred.id)).map(credentialGrantToEntry)

	if (cred.principal_id === null) {
		// Anonymous: the frozen inline grants ARE the permission set (delegation-checked at issue).
		return { ok: true, subject: cred.id, label: cred.label, permissions: inline }
	}

	const principal = await services.db.getPrincipalById(cred.principal_id)
	if (!principal) {
		return { ok: false, reason: 'unknown_principal' }
	}
	if (principalStatus(principal) === 'disabled') {
		return { ok: false, reason: 'disabled' }
	}

	const resolved = principal.type === 'service'
		? await resolveServicePermissions(services.db, principal, app)
		: (await resolveUserPermissions({
			db: services.db,
			identity: services.identity,
			principal,
			cookie: null,
			origin: null,
			bootstrapAdmins: services.config.bootstrapAdmins,
			app,
		})).permissions

	// Inline grants on a bound credential are a DOWNSCOPE restriction: keep only what the principal
	// actually holds (effective = resolve(principal) ∩ inline). No inline → the principal's full set.
	const permissions = inline.length === 0 ? resolved : inline.filter((e) => permits(resolved, e.action, e.scope ?? undefined))
	return { ok: true, subject: principal.id, type: principal.type, label: principal.label, permissions }
}

/** A `credential_grants` row → a `PermissionEntry` (source 'grant'; both scope cols null = global). */
function credentialGrantToEntry(row: CredentialGrantRow): PermissionEntry {
	const scope: Scope | null = row.scope_type === null || row.scope_value === null ? null : { type: row.scope_type, value: row.scope_value }
	return { action: row.action, scope, source: 'grant' }
}

/** Sign an access token with the isolate's active signing key. Shared by every mint front. */
export async function signAccessToken(
	services: Services,
	env: MintEnv,
	params: Omit<Parameters<typeof buildAccessClaims>[0], 'iss'>,
): Promise<string> {
	const signer = await getSigner(env)
	const claims: AccessTokenClaims = buildAccessClaims({ ...params, iss: services.config.issuer })
	return signer.sign(claims)
}
