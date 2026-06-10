import type { DomainEvent, PrincipalType } from '@propustka/core'
import { matchAction } from '@propustka/core'
import type { AuthContext, AuthFailure, Capability, CapabilityFailure, IssueCapabilityRequest, IssuedCapability, IssueFailure } from './types'

/**
 * Config for the fake. `deny` is a list of action patterns (same `*`/`prefix.*` matching as
 * roles) that `can()` returns false for — so apps can exercise their 403 paths in dev. A
 * plain allow-all would never let a forbidden branch run until production. `principal`
 * overrides the fixed fake identity (id/label/type).
 */
export interface FakeIamConfig {
	deny?: string[]
	principal?: {
		id?: string
		label?: string
		type?: PrincipalType
	}
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

/** True when `action` matches any pattern in the deny list. */
function isDenied(deny: string[], action: string): boolean {
	for (const pattern of deny) {
		if (matchAction(pattern, action)) {
			return true
		}
	}
	return false
}

// ── Fake surfaces ───────────────────────────────────────────────────────────────

class FakeAuthContext implements AuthContext {
	readonly ok = true

	constructor(private readonly deny: string[]) {}

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
 * Drop-in for `IamClient` with an identical public interface, selectable by the app via an
 * env flag for `wrangler dev`. Fixed identity, no Access, no IAM Worker. `can()` allows
 * everything except the `deny` list, so 403 paths are still testable in dev.
 */
export class FakeIamClient {
	private readonly deny: string[]
	private readonly identity: FakeIdentity

	constructor(config?: FakeIamConfig) {
		this.deny = config?.deny ?? []
		this.identity = resolveIdentity(config)
	}

	authenticate(_req: Request): Promise<AuthContext | AuthFailure> {
		return Promise.resolve(new FakeAuthContext(this.deny))
	}

	redeemCapability(_req: Request, _token: string): Promise<Capability | CapabilityFailure> {
		return Promise.resolve(new FakeCapability(this.deny))
	}

	issueCapability(_req: Request, _input: IssueCapabilityRequest): Promise<IssuedCapability | IssueFailure> {
		const suffix = crypto.randomUUID()
		return Promise.resolve({ ok: true, token: `fake-token-${suffix}`, id: `fake-${this.identity.id}-${suffix}` })
	}
}
