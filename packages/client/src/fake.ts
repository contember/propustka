import type { PermissionEntry, PrincipalListItem, PrincipalType } from '@propustka/core'
import type {
	IssuedJwt,
	IssuedKey,
	IssueFailure,
	IssueJwtRequest,
	IssueKeyRequest,
	ListPrincipalsFailure,
	PrincipalList,
	RevokedKey,
	RevokeFailure,
} from './types'

/**
 * A fixed dev persona — an identity plus a permissions array. Used purely as a `listPrincipals`
 * roster entry for `wrangler dev` (the people picker / actor list) without a running IAM Worker.
 * `permissions` is data the app may carry on the persona; the fake itself does not enforce it
 * (authorization in the native world is the worker-issued token the SDK's `PropustkaAuth` verifies).
 */
export interface FakePersona {
	id: string
	label: string
	type?: PrincipalType
	/** The persona's permission entries (carried as data; not enforced by the fake). */
	permissions: PermissionEntry[]
}

/**
 * Config for the fake management client. `principal` sets the single fixed dev identity surfaced by
 * `listPrincipals` (id/label/type). `personas`, when set, instead supplies the enumerable dev roster
 * `listPrincipals` returns. Neither affects issue/revoke — those are an in-memory registry.
 */
export interface FakeIamConfig {
	principal?: {
		id?: string
		label?: string
		type?: PrincipalType
	}
	personas?: Record<string, FakePersona>
}

interface FakeIdentity {
	id: string
	label: string
	type: PrincipalType
}

function resolveIdentity(config: FakeIamConfig | undefined): FakeIdentity {
	return {
		id: config?.principal?.id ?? 'fake-principal',
		label: config?.principal?.label ?? 'fake@example.com',
		type: config?.principal?.type ?? 'user',
	}
}

// ── FakeIamClient ─────────────────────────────────────────────────────────────

/**
 * Drop-in for `IamClient`'s MANAGEMENT surface (`listPrincipals` / `issueKey` / `issueJwt` /
 * `revokeKey`), selectable by the app via an env flag for `wrangler dev`. No Access, no IAM Worker:
 * `listPrincipals` returns the configured roster, and issue/revoke share an in-memory credential
 * registry so a key's `issueKey → revokeKey` lifecycle stays consistent. The authentication/gate path
 * is `PropustkaAuth` (verified against the worker), not this client.
 */
export class FakeIamClient {
	private readonly identity: FakeIdentity
	private readonly personas?: Record<string, FakePersona>
	// In-memory credential registry so issueKey → revokeKey stay consistent in dev/tests (no IAM
	// Worker locally): tracks every issued credential id and the subset that has been revoked.
	private readonly issuedIds = new Set<string>()
	private readonly revokedIds = new Set<string>()

	constructor(config?: FakeIamConfig) {
		this.identity = resolveIdentity(config)
		this.personas = config?.personas
	}

	listPrincipals(_req: Request): Promise<PrincipalList | ListPrincipalsFailure> {
		// PERSONA mode: the configured personas ARE the dev roster (enumerable). SIMPLE mode has no
		// enumerable set, so fall back to the single fixed identity. A user's label is their email;
		// services carry none.
		const toItem = (id: string, label: string, type: PrincipalType): PrincipalListItem => ({
			id,
			type,
			label,
			email: type === 'user' ? label : null,
			disabled: false,
		})
		const principals: PrincipalListItem[] = this.personas
			? Object.values(this.personas).map((p) => toItem(p.id, p.label, p.type ?? 'user'))
			: [toItem(this.identity.id, this.identity.label, this.identity.type)]
		return Promise.resolve({ ok: true, principals })
	}

	issueKey(_req: Request, input: IssueKeyRequest): Promise<IssuedKey | IssueFailure> {
		const suffix = crypto.randomUUID()
		const token = `px_fake-${suffix}`
		const id = `fake-cred-${suffix}`
		this.issuedIds.add(id)
		// `service` mode mints a fresh fake service principal and binds the key to it; the bound
		// principal id is the returned handle. A self-bind echoes the requested principal id.
		const principalId = input.service !== undefined ? `fake-service-${suffix}` : input.principalId
		return Promise.resolve({ ok: true, token, id, ...(principalId === undefined ? {} : { principalId }) })
	}

	issueJwt(_req: Request, _input: IssueJwtRequest): Promise<IssuedJwt | IssueFailure> {
		const suffix = crypto.randomUUID()
		// A fake passthrough token (audit-only, not revocable) — no registry entry. The `expiresAt`
		// is a fixed 5-minute window so callers can exercise the shape without real signing.
		return Promise.resolve({ ok: true, token: `fake-jwt-${suffix}`, expiresAt: 300, id: `fake-jwt-${suffix}` })
	}

	revokeKey(_req: Request, id: string): Promise<RevokedKey | RevokeFailure> {
		if (!this.issuedIds.has(id)) {
			return Promise.resolve({ ok: false, reason: 'not_found', status: 404 })
		}
		if (this.revokedIds.has(id)) {
			return Promise.resolve({ ok: true, revoked: false })
		}
		this.revokedIds.add(id)
		return Promise.resolve({ ok: true, revoked: true })
	}
}
