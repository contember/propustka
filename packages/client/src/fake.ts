import type { DomainEvent, PermissionEntry, PrincipalType } from '@propustka/core'
import { matchAction, permits, scopedProjects } from '@propustka/core'
import type { AuthContext, AuthFailure, Capability, CapabilityFailure, IssueCapabilityRequest, IssuedCapability, IssueFailure, PrincipalIdentity } from './types'

/**
 * A fixed dev persona: an identity plus a real permissions array. When `FakeIamConfig.personas`
 * is set, the fake resolves one of these per request (by a cookie / header key) and backs
 * `can()` / `scopedTo()` with the SAME `permits` / `scopedProjects` core logic the real client
 * uses — so role/scope behaviour (admin vs app-wide vs project-scoped) is exercisable in dev and
 * browser tests without Cloudflare Access or a running IAM Worker.
 */
export interface FakePersona {
	id: string
	label: string
	type?: PrincipalType
	/** The resolved permission entries — real `permits`/`scopedProjects` semantics (not allow-all). */
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

	can(action: string, _scope?: { project?: string }): boolean {
		// Allow everything except denied actions — regardless of scope.
		return !isDenied(this.deny, action)
	}

	scopedTo(_action: string, _dimension = 'project'): string[] | null {
		// Unrestricted: the fake identity may see everything.
		return null
	}

	audit(_event: DomainEvent): Promise<void> {
		return Promise.resolve()
	}
}

/** Persona-backed context (persona mode) — real `permits` / `scopedProjects` semantics. */
class PersonaAuthContext implements AuthContext {
	readonly ok = true
	readonly principal: PrincipalIdentity

	constructor(private readonly persona: FakePersona) {
		this.principal = { id: persona.id, type: persona.type ?? 'user', label: persona.label }
	}

	can(action: string, scope?: { project?: string }): boolean {
		return permits(this.persona.permissions, action, scope?.project)
	}

	scopedTo(action: string, _dimension = 'project'): string[] | null {
		return scopedProjects(this.persona.permissions, action)
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

	constructor(config?: FakeIamConfig) {
		this.deny = config?.deny ?? []
		this.identity = resolveIdentity(config)
		this.personas = config?.personas
		this.personaCookie = config?.personaCookie ?? DEFAULT_PERSONA_COOKIE
		this.personaHeader = config?.personaHeader ?? DEFAULT_PERSONA_HEADER
		this.defaultPersona = config?.defaultPersona
	}

	authenticate(req: Request): Promise<AuthContext | AuthFailure> {
		if (this.personas) {
			const key = readCookie(req, this.personaCookie) ?? req.headers.get(this.personaHeader) ?? this.defaultPersona
			const persona = key ? this.personas[key] : undefined
			if (!persona) {
				// Selected an unknown persona (or none, with no default) → behave like a real
				// authenticated-but-unrecognised principal.
				return Promise.resolve({ ok: false, reason: 'unknown_principal', status: 403 })
			}
			return Promise.resolve(new PersonaAuthContext(persona))
		}
		return Promise.resolve(new FakeAuthContext(this.deny, this.identity))
	}

	redeemCapability(_req: Request, _token: string): Promise<Capability | CapabilityFailure> {
		return Promise.resolve(new FakeCapability(this.deny))
	}

	issueCapability(_req: Request, _input: IssueCapabilityRequest): Promise<IssuedCapability | IssueFailure> {
		const suffix = crypto.randomUUID()
		return Promise.resolve({ ok: true, token: `fake-token-${suffix}`, id: `fake-${this.identity.id}-${suffix}` })
	}
}
