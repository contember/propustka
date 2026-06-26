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

// ── Per-path access gates (the propustka-native front door, enforced IN-PROCESS by the SDK) ──
//
// Replaces the deleted Cloudflare-Access edge model (AppAccess/AccessAppDecl/AccessRule). There is
// no reconcile and no worker endpoint for these: gate rules are pure SDK config, consumed only by
// `PropustkaAuth` to decide WHICH credential KIND a path requires — the in-process successor to the
// CF Access edge decision (CF Access is gone). Three kinds mirror the three old edge decisions:
//   - public  → no credential (the old `bypass`/everyone carve-out)
//   - service → a machine `px_` key or passthrough JWT (the old `non_identity`/service-token gate)
//   - human   → a logged-in human via `px_session`/`px_token` (the old `allow`-by-audience gate)
// WHO is an admitted human stays centrally owned by propustka (decided at `/auth/callback`, the
// admission allowlist), exactly as the old central edge audience did — a `human` gate only asserts
// "a resolved user principal exists". Auth-surface paths (`/auth/*`, `/.well-known/jwks.json`) live
// on PROPUSTKA's host, not the app's, so apps never declare them.

/** Where a propustka credential (a `px_` key or a passthrough JWT) rides on a request. */
export interface CredentialLocation {
	/** Transport carrying the credential. */
	in: 'header' | 'query' | 'cookie'
	/** Header / query-param / cookie name. A header value may be bare or `Bearer <token>`. */
	name: string
}

/** What a matched path requires. The discriminant `kind` mirrors the three old edge decisions. */
export type GateKind =
	/** Anyone — no credential. Terminal; resolves to an ANONYMOUS AuthContext (`principal: null`). */
	| { kind: 'public' }
	/**
	 * A machine `px_` key or a passthrough JWT — a bearer (default `Authorization: Bearer`) or the
	 * declared `credential` location. ABSENT → falls through to the next matching rule; PRESENT but
	 * invalid → fail closed (no fall-through).
	 */
	| { kind: 'service'; credential?: CredentialLocation }
	/** A logged-in human (a `user` principal via the `px_session`/`px_token` cookies). */
	| { kind: 'human' }

/**
 * One per-path gate rule. The array order on `AppGates.rules` is the PRECEDENCE: the first rule whose
 * `path` matches AND whose required credential is present is enforced. A matching rule whose credential
 * is ABSENT falls through to the next matching rule; a request matching NO rule is denied (fail-closed).
 * `path` is a glob where `*` matches any run of chars (e.g. `/api/v1/*`); anchored.
 */
export type GateRule = { path: string } & GateKind

/** An app's full per-path gate declaration, enforced by its `PropustkaAuth` middleware. */
export interface AppGates {
	rules: GateRule[]
}

// ── Access edge rules (LEGACY — Cloudflare Access front door) ───────────────────
//
// DEPRECATED. Superseded by `AppGates` above. Retained only until the worker's CF-Access edge
// reconcile surface (`reconcile-access.ts`, `PUT /admin/apps/:app/access`, `cfaccess.ts`,
// `propustka.access.ts`) is deleted, then these go too. New apps declare `AppGates`, not this.

/** One Access edge rule. The array order on an app is its Cloudflare precedence order. */
export type AccessRule =
	/** Machines: a `non_identity` policy including "any valid service token". */
	| { kind: 'service-auth' }
	/** Humans: an `allow` policy. Supply at least one of `emailDomains` / `emails`. */
	| { kind: 'human'; emailDomains?: string[]; emails?: string[] }
	/** Anonymous: a `bypass` policy including everyone (for public carve-out paths). */
	| { kind: 'public' }

/** One Cloudflare Access application this propustka app fronts, with its edge rules. */
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
