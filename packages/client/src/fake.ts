import type { DomainEvent, PermissionEntry, PrincipalListItem, PrincipalType, Scope } from '@propustka/core'
import { matchAction, permits, scopedValues } from '@propustka/core'
import type {
	AuthContext,
	AuthFailure,
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
	// In-memory credential registry so issueKey → revokeKey stay consistent in dev/tests (no IAM
	// Worker locally): tracks every issued credential id and the subset that has been revoked.
	private readonly issuedIds = new Set<string>()
	private readonly revokedIds = new Set<string>()

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
