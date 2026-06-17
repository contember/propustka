export type PrincipalType = 'user' | 'service'

/**
 * Where a resolved permission entry came from. Used for debuggability in the admin UI
 * ("why does this user have this permission?"); `can()`/`scopedTo()` ignore it.
 *  - 'grant'             — explicit `grants` row
 *  - 'bootstrap'         — IAM_BOOTSTRAP_ADMINS env match (resolution-time only)
 *  - `group:${groupRef}` — IdP group → role mapping (the `<org>/<team>` ref)
 */
export type PermissionSource = 'grant' | 'bootstrap' | `group:${string}`

/**
 * A flat, app-owned scope coordinate — one dimension (`type`) and an opaque value.
 * Dimensions are INDEPENDENT: there is NO hierarchy/containment between them.
 * `value` is an opaque app-owned string; core never validates it.
 */
export interface Scope {
	type: string
	value: string
}

export interface PermissionEntry {
	action: string
	/** null = global / all scopes */
	scope: Scope | null
	source: PermissionSource
}

/**
 * Domain event apps emit. Only the app knows what changed.
 *
 * IMPORTANT: `diff`/`metadata` may carry sensitive values (settings can hold secrets).
 * The app MUST redact secret material before passing them — audit storage is verbatim
 * and long-lived; the IAM Worker stores what it receives as-is.
 */
export interface DomainEvent {
	action: string
	resourceType: string
	resourceId?: string
	diff?: unknown
	metadata?: unknown
}

export interface RoleDef {
	name: string
	description?: string
	permissions: string[]
}

/** One scope dimension an app exposes (flat, independent). */
export interface AppScopeDef {
	type: string
	label?: string
}

/** One action in an app's catalog (used for validation + admin UI discovery). */
export interface AppActionDef {
	action: string
	description?: string
}

/** An app's full authz vocabulary, declared in the app's code, reconciled into Propustka. */
export interface AppSchema {
	scopes: AppScopeDef[]
	actions: AppActionDef[]
	/** role_key -> def; these are origin='app' roles. */
	roles: Record<string, RoleDef>
}

// ── Access edge rules (the Cloudflare Access front door, declared as code) ──────
//
// Parallel to `AppSchema`, but for the EDGE (Cloudflare Access) rather than authz. An app
// declares which rules front its hostnames; Propustka reconciles them into Cloudflare as
// account-level REUSABLE policies attached to the app's Access application(s) — the new CF
// model. Three rule kinds map to the three Access decisions:
//   - service-auth → `non_identity` / "any valid service token" (machines: service tokens)
//   - human        → `allow` by email domain / explicit emails (operators in a browser)
//   - public       → `bypass` / everyone (public carve-out paths)
// Reconcile is idempotent and owns only the policies it manages (a reserved name prefix), never
// touching admin-composed ones — mirroring the schema reconcile's origin='app' vs 'custom' rule.

/** One Access edge rule. The array order on an app is its Cloudflare precedence order. */
export type AccessRule =
	/** Machines: a `non_identity` policy including "any valid service token". */
	| { kind: 'service-auth' }
	/** Humans: an `allow` policy. Supply at least one of `emailDomains` / `emails`. */
	| { kind: 'human'; emailDomains?: string[]; emails?: string[] }
	/** Anonymous: a `bypass` policy including everyone (for public carve-out paths). */
	| { kind: 'public' }

/**
 * One Cloudflare Access application this propustka app fronts, with its edge rules. A single
 * propustka app id may map to MORE THAN ONE CF app — e.g. a main allow-gated host plus a
 * separate bypass carve-out for its public paths (its own `destinations` + a `public` rule).
 */
export interface AccessAppDecl {
	/** Stable key, unique within the declaration. Drives the managed policy name + CF-app match. */
	key: string
	/** The Cloudflare Access application name (matched/created by name). */
	name: string
	/** self_hosted destinations — host or host/path, e.g. `opice.contember.com` / `opice.contember.com/s`. */
	destinations: string[]
	/** CF session duration (e.g. `24h`); the worker applies a default when omitted. */
	sessionDuration?: string
	/** The edge rules to converge onto this CF app, in precedence order (first = highest). */
	rules: AccessRule[]
}

/** An app's full Access-edge declaration, reconciled into Cloudflare by Propustka. */
export interface AppAccess {
	apps: AccessAppDecl[]
}

/**
 * App-aware role lookup. The worker layers a built-in cross-app source (admin) over a
 * per-app DB source. `app` is the calling app id; null = cross-app/built-in only.
 */
export interface RoleSource {
	getRole(app: string | null, key: string): RoleDef | undefined
	listRoles(app: string | null): Record<string, RoleDef>
}
