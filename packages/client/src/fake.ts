import type { DomainEvent, PermissionEntry, PrincipalListItem, PrincipalType, Scope } from '@propustka/core'
import { matchAction, permits, scopedValues } from '@propustka/core'
import type {
	AuthContext,
	AuthFailure,
	Capability,
	CapabilityFailure,
	IssueCapabilityRequest,
	IssuedCapability,
	IssuedServiceToken,
	IssueFailure,
	IssueServiceTokenFailure,
	IssueServiceTokenRequest,
	ListPrincipalsFailure,
	PrincipalIdentity,
	PrincipalList,
	RevokedCapability,
	RevokedServiceToken,
	RevokeFailure,
	RevokeServiceTokenFailure,
	RotatedServiceToken,
	RotateServiceTokenFailure,
} from './types'

/** A service principal minted in-memory by the fake's `issueServiceToken`, resolved on authenticate. */
interface FakeServiceToken {
	principalId: string
	clientSecret: string
	label: string
	permissions: PermissionEntry[]
}

/** Cloudflare injects the service token's client id as this header (here it's sent directly — no edge). */
const ACCESS_CLIENT_ID_HEADER = 'CF-Access-Client-Id'

/**
 * A fixed dev persona: an identity plus a real permissions array. When `FakeIamConfig.personas`
 * is set, the fake resolves one of these per request (by a cookie / header key) and backs
 * `can()` / `scopedTo()` with the SAME `permits` / `scopedValues` core logic the real client
 * uses — so role/scope behaviour (admin vs app-wide vs scoped) is exercisable in dev and
 * browser tests without Cloudflare Access or a running IAM Worker.
 */
export interface FakePersona {
	id: string
	label: string
	type?: PrincipalType
	/** The resolved permission entries — real `permits`/`scopedValues` semantics (not allow-all). */
	permissions: PermissionEntry[]
}

/**
 * Config for the fake. Two modes:
 *
 *  - SIMPLE (default): a single fixed identity, `can()` allows everything except the `deny`
 *    action patterns (same `*`/`prefix.*` matching as roles) so 403 paths are still testable.
 *    `principal` overrides the fixed identity (id/label/type).
 *
 *  - PERSONA: set `personas` (keyed by an opaque selector, e.g. an email) to make the fake
 *    impersonate a specific principal per request, with real permission semantics. The active
 *    persona key is read from the `personaCookie` (default `propustka_dev_principal`) or the
 *    `personaHeader` (default `X-Dev-Principal`), falling back to `defaultPersona`. A cookie is
 *    what browser E2E uses (it rides every navigation + fetch); the header suits CLI/fetch. An
 *    unknown/absent key with no default resolves to `unknown_principal` (403) — the same shape a
 *    real unrecognised principal gets.
 */
export interface FakeIamConfig {
	deny?: string[]
	principal?: {
		id?: string
		label?: string
		type?: PrincipalType
	}
	personas?: Record<string, FakePersona>
	/** Cookie carrying the active persona key (browser E2E). Default `propustka_dev_principal`. */
	personaCookie?: string
	/** Header carrying the active persona key (fetch/CLI). Default `X-Dev-Principal`. */
	personaHeader?: string
	/** Persona key used when neither cookie nor header is present. */
	defaultPersona?: string
	/**
	 * Dynamic per-request persona resolver — the most flexible mode (takes precedence over
	 * `personas`/`deny`). The app derives the persona however it likes (e.g. a dev cookie →
	 * a directory lookup), so personas need not be enumerated up front. Returning `null`
	 * resolves to `unknown_principal` (403), like a real unrecognised principal.
	 */
	resolve?: (req: Request) => FakePersona | null | Promise<FakePersona | null>
}

interface FakeIdentity {
	id: string
	label: string
	type: PrincipalType
}

const DEFAULT_PERSONA_COOKIE = 'propustka_dev_principal'
const DEFAULT_PERSONA_HEADER = 'X-Dev-Principal'

function resolveIdentity(config: FakeIamConfig | undefined): FakeIdentity {
	return {
		id: config?.principal?.id ?? 'fake-principal',
		label: config?.principal?.label ?? 'fake@example.com',
		type: config?.principal?.type ?? 'user',
	}
}

/** True when `action` matches any pattern in the deny list. */
function isDenied(deny: string[], action: string): boolean {
	for (const pattern of deny) {
		if (matchAction(pattern, action)) {
			return true
		}
	}
	return false
}

/** Read a single cookie value out of a request's Cookie header. Returns null when absent. */
function readCookie(req: Request, name: string): string | null {
	const header = req.headers.get('Cookie')
	if (!header) {
		return null
	}
	for (const part of header.split(';')) {
		const eq = part.indexOf('=')
		if (eq === -1) {
			continue
		}
		if (part.slice(0, eq).trim() === name) {
			return decodeURIComponent(part.slice(eq + 1).trim())
		}
	}
	return null
}

// ── Fake surfaces ───────────────────────────────────────────────────────────────

/** Allow-all-except-deny context (simple mode). */
class FakeAuthContext implements AuthContext {
	readonly ok = true
	readonly principal: PrincipalIdentity

	constructor(
		private readonly deny: string[],
		identity: FakeIdentity,
	) {
		this.principal = { id: identity.id, type: identity.type, label: identity.label }
	}

	can(action: string, _scope?: Scope): boolean {
		// Allow everything except denied actions — regardless of scope.
		return !isDenied(this.deny, action)
	}

	scopedTo(_action: string, _dimension: string): string[] | null {
		// Unrestricted: the fake identity may see everything.
		return null
	}

	audit(_event: DomainEvent): Promise<void> {
		return Promise.resolve()
	}
}

/** Persona-backed context (persona mode) — real `permits` / `scopedValues` semantics. */
class PersonaAuthContext implements AuthContext {
	readonly ok = true
	readonly principal: PrincipalIdentity

	constructor(private readonly persona: FakePersona) {
		this.principal = { id: persona.id, type: persona.type ?? 'user', label: persona.label }
	}

	can(action: string, scope?: Scope): boolean {
		return permits(this.persona.permissions, action, scope)
	}

	scopedTo(action: string, dimension: string): string[] | null {
		return scopedValues(this.persona.permissions, action, dimension)
	}

	audit(_event: DomainEvent): Promise<void> {
		return Promise.resolve()
	}
}

class FakeCapability implements Capability {
	readonly ok = true

	constructor(private readonly deny: string[]) {}

	can(action: string, _resource: string): boolean {
		return !isDenied(this.deny, action)
	}

	audit(_event: DomainEvent): Promise<void> {
		return Promise.resolve()
	}
}

// ── FakeIamClient ─────────────────────────────────────────────────────────────

/**
 * Drop-in for `IamClient` with an identical public interface, selectable by the app via an env
 * flag for `wrangler dev`. No Access, no IAM Worker. In SIMPLE mode `can()` allows everything
 * except the `deny` list; in PERSONA mode it impersonates the request's selected persona with
 * real permission semantics (see `FakeIamConfig`).
 */
export class FakeIamClient {
	private readonly deny: string[]
	private readonly identity: FakeIdentity
	private readonly personas?: Record<string, FakePersona>
	private readonly personaCookie: string
	private readonly personaHeader: string
	private readonly defaultPersona?: string
	private readonly resolve?: (req: Request) => FakePersona | null | Promise<FakePersona | null>
	// In-memory capability registry so issue → redeem → revoke stay consistent in dev/tests
	// (no IAM Worker locally). Maps the plaintext token to its id, tracks every issued id,
	// and the subset that has been revoked — so a redeemed-then-revoked token reads 'revoked'.
	private readonly issuedTokens = new Map<string, string>()
	private readonly issuedIds = new Set<string>()
	private readonly revokedIds = new Set<string>()
	// In-memory service-token registry (keyed by clientId) so a locally minted service token
	// authenticates to its service principal — opice local-dev ingest/read without an Access edge.
	private readonly serviceTokens = new Map<string, FakeServiceToken>()
	private readonly revokedServicePrincipals = new Set<string>()

	constructor(config?: FakeIamConfig) {
		this.deny = config?.deny ?? []
		this.identity = resolveIdentity(config)
		this.personas = config?.personas
		this.personaCookie = config?.personaCookie ?? DEFAULT_PERSONA_COOKIE
		this.personaHeader = config?.personaHeader ?? DEFAULT_PERSONA_HEADER
		this.defaultPersona = config?.defaultPersona
		this.resolve = config?.resolve
	}

	async authenticate(req: Request): Promise<AuthContext | AuthFailure> {
		// A machine request carrying a service-token client id resolves to the registered service
		// principal (the local stand-in for the Access edge → service JWT → principal flow). The
		// secret is not validated — the fake is a dev convenience, not a validator.
		const clientId = req.headers.get(ACCESS_CLIENT_ID_HEADER)
		if (clientId !== null) {
			const service = this.serviceTokens.get(clientId)
			if (!service) {
				return { ok: false, reason: 'unknown_principal', status: 403 }
			}
			return new PersonaAuthContext({
				id: service.principalId,
				label: service.label,
				type: 'service',
				permissions: service.permissions,
			})
		}
		// Dynamic resolver wins — the app decides the persona per request.
		if (this.resolve) {
			const persona = await this.resolve(req)
			if (!persona) {
				return { ok: false, reason: 'unknown_principal', status: 403 }
			}
			return new PersonaAuthContext(persona)
		}
		if (this.personas) {
			const key = readCookie(req, this.personaCookie) ?? req.headers.get(this.personaHeader) ?? this.defaultPersona
			const persona = key ? this.personas[key] : undefined
			if (!persona) {
				// Selected an unknown persona (or none, with no default) → behave like a real
				// authenticated-but-unrecognised principal.
				return { ok: false, reason: 'unknown_principal', status: 403 }
			}
			return new PersonaAuthContext(persona)
		}
		return new FakeAuthContext(this.deny, this.identity)
	}

	listPrincipals(_req: Request): Promise<PrincipalList | ListPrincipalsFailure> {
		// PERSONA mode: the configured personas ARE the dev roster (enumerable). SIMPLE/resolve
		// mode has no enumerable set, so fall back to the single fixed identity. A user's label
		// is their email; services carry none.
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

	redeemCapability(_req: Request, token: string): Promise<Capability | CapabilityFailure> {
		// A token issued by THIS fake and since revoked reads 'revoked' (404), like the real
		// Worker. Tokens we never issued (e.g. a hand-written one) still redeem allow-all — the
		// fake is a dev/test convenience, not a validator.
		const id = this.issuedTokens.get(token)
		if (id && this.revokedIds.has(id)) {
			return Promise.resolve({ ok: false, reason: 'revoked', status: 404 })
		}
		return Promise.resolve(new FakeCapability(this.deny))
	}

	issueCapability(_req: Request, _input: IssueCapabilityRequest): Promise<IssuedCapability | IssueFailure> {
		const suffix = crypto.randomUUID()
		const token = `fake-token-${suffix}`
		const id = `fake-${this.identity.id}-${suffix}`
		this.issuedTokens.set(token, id)
		this.issuedIds.add(id)
		return Promise.resolve({ ok: true, token, id })
	}

	revokeCapability(_req: Request, tokenId: string): Promise<RevokedCapability | RevokeFailure> {
		if (!this.issuedIds.has(tokenId)) {
			return Promise.resolve({ ok: false, reason: 'not_found', status: 404 })
		}
		if (this.revokedIds.has(tokenId)) {
			return Promise.resolve({ ok: true, revoked: false })
		}
		this.revokedIds.add(tokenId)
		return Promise.resolve({ ok: true, revoked: true })
	}

	issueServiceToken(_req: Request, input: IssueServiceTokenRequest): Promise<IssuedServiceToken | IssueServiceTokenFailure> {
		const suffix = crypto.randomUUID()
		const clientId = `fake-client-${suffix}`
		const clientSecret = `fake-secret-${suffix}`
		const principalId = `fake-service-${suffix}`
		const permissions: PermissionEntry[] = input.permissions.map((action) => ({ action, scope: input.scope ?? null, source: 'grant' }))
		this.serviceTokens.set(clientId, { principalId, clientSecret, label: input.label, permissions })
		return Promise.resolve({ ok: true, clientId, clientSecret, apiKey: `px_fake-${suffix}`, principalId, tokenId: `fake-token-${suffix}` })
	}

	revokeServiceToken(_req: Request, principalId: string): Promise<RevokedServiceToken | RevokeServiceTokenFailure> {
		const found = this.findServiceByPrincipal(principalId)
		if (!found) {
			// Already revoked reads as an idempotent no-op; never-seen reads as not_found.
			if (this.revokedServicePrincipals.has(principalId)) {
				return Promise.resolve({ ok: true, revoked: false })
			}
			return Promise.resolve({ ok: false, reason: 'not_found', status: 404 })
		}
		this.serviceTokens.delete(found.clientId)
		this.revokedServicePrincipals.add(principalId)
		return Promise.resolve({ ok: true, revoked: true })
	}

	rotateServiceToken(_req: Request, principalId: string): Promise<RotatedServiceToken | RotateServiceTokenFailure> {
		const found = this.findServiceByPrincipal(principalId)
		if (!found) {
			return Promise.resolve({ ok: false, reason: 'not_found', status: 404 })
		}
		const suffix = crypto.randomUUID()
		const clientSecret = `fake-secret-${suffix}`
		// Mutate the stored entry (same reference held in the map): client_id + principal unchanged.
		found.service.clientSecret = clientSecret
		return Promise.resolve({ ok: true, clientId: found.clientId, clientSecret, apiKey: `px_fake-${suffix}`, tokenId: `fake-token-${suffix}` })
	}

	/** Locate a registered service token by its principal id (small N in dev — linear scan). */
	private findServiceByPrincipal(principalId: string): { clientId: string; service: FakeServiceToken } | null {
		for (const [clientId, service] of this.serviceTokens) {
			if (service.principalId === principalId) {
				return { clientId, service }
			}
		}
		return null
	}
}
