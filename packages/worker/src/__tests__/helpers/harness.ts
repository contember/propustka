import { Database, type SQLQueryBindings } from 'bun:sqlite'
import { createLocalJWKSet, exportJWK, generateKeyPair, type JSONWebKeySet, type JWTPayload, SignJWT } from 'jose'
import type { CfAccess } from '../../cfaccess'
import { Db } from '../../db'
import { IdentityClient } from '../../identity'
import { type AccessApps, JwtValidator } from '../../jwt'
import { OidcClient, type OidcMetadata } from '../../oidc'
import { hashToken } from '../../secret'
import type { Config, Services } from '../../services'
import { FakeCfAccess } from './fake-cfaccess'
import { allMigrations } from './migrations'

/**
 * Shared test harness for the worker's auth/admin flows. Stands up:
 *   - a real in-memory `bun:sqlite` DB with the production migration applied,
 *     wrapped in a small D1-compatible adapter so `new Db(...)` runs against it
 *     exactly as it does over D1 (mirrors the schema.test.ts pattern);
 *   - a `JwtValidator` fed a local RSA JWKS (the constructor's 3rd-arg seam) plus a
 *     `signToken` helper that mints valid Access tokens with the matching key
 *     (mirrors the jwt.test.ts pattern);
 *   - a real `IdentityClient` (group resolution returns `unavailable` with no
 *     network when cookie/origin are null — which every test here passes);
 *   - `makeServices({ environment, accessApps })` assembling a plain `Services`
 *     from these real instances.
 *
 * Nothing here mocks the modules under test — jose performs the genuine
 * cryptographic verification and the SQL runs against the real schema.
 */

// ── Access config used across the suite ───────────────────────────────────────

/** Offline OIDC discovery metadata for the harness default client (no network in tests). */
export const HARNESS_OIDC_METADATA: OidcMetadata = {
	issuer: 'https://idp.test',
	authorizationEndpoint: 'https://idp.test/authorize',
	tokenEndpoint: 'https://idp.test/token',
	jwksUri: 'https://idp.test/jwks',
}

export const TEAM = 'https://team.cloudflareaccess.com'
const ALG = 'RS256'
/** The default aud tag → app id map used when a test wants real Access configured. */
export const DEFAULT_ACCESS_APPS: AccessApps = { 'aud-iam-tag': 'iam-admin' }
/** The aud tag a signed token carries by default (a key of DEFAULT_ACCESS_APPS). */
export const DEFAULT_AUD = 'aud-iam-tag'

// ── One shared RSA key pair + local JWKS for the whole suite ──────────────────
// The validator is given a createLocalJWKSet resolver bound to the public key, so
// jwtVerify resolves the signing key locally (no network) while still doing the
// real signature check; signToken signs with the matching private key.

const { publicKey, privateKey } = await generateKeyPair(ALG)
const jwk = await exportJWK(publicKey)
jwk.kid = 'test-key-1'
jwk.alg = ALG
jwk.use = 'sig'
const jwks: JSONWebKeySet = { keys: [jwk] }
const localJwks = createLocalJWKSet(jwks)

export interface SignClaims extends JWTPayload {
	email?: string
	sub?: string
	common_name?: string
}

export interface SignOptions {
	/** aud to set; defaults to DEFAULT_AUD. */
	audience?: string | string[]
}

/** Mint a valid Access token signed with the local key the validator trusts. */
export async function signToken(claims: SignClaims, opts: SignOptions = {}): Promise<string> {
	return new SignJWT(claims)
		.setProtectedHeader({ alg: ALG, kid: 'test-key-1' })
		.setIssuer(TEAM)
		.setIssuedAt()
		.setAudience(opts.audience ?? DEFAULT_AUD)
		.setExpirationTime('1h')
		.sign(privateKey)
}

// ── D1-compatible adapter over bun:sqlite ─────────────────────────────────────
// `Db` talks to the async D1 surface (`prepare().bind().first()/.all()/.run()` and
// `batch()`). bun:sqlite is synchronous, so we wrap it. Typed end-to-end (the bun
// `Statement<ReturnType>` generic carries the row type through), so no casts.

class TestD1PreparedStatement implements D1PreparedStatement {
	private params: SQLQueryBindings[] = []

	constructor(private readonly db: Database, private readonly sql: string) {}

	bind(...values: unknown[]): D1PreparedStatement {
		const next = new TestD1PreparedStatement(this.db, this.sql)
		next.params = values.map((v) => toBinding(v))
		return next
	}

	first<T = Record<string, unknown>>(colName: string): Promise<T | null>
	first<T = Record<string, unknown>>(): Promise<T | null>
	first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
		const row = this.db.query<T, SQLQueryBindings[]>(this.sql).get(...this.params)
		if (row === null) {
			return Promise.resolve(null)
		}
		if (colName !== undefined) {
			return Promise.resolve(pluck<T>(row, colName))
		}
		return Promise.resolve(row)
	}

	all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
		const results = this.db.query<T, SQLQueryBindings[]>(this.sql).all(...this.params)
		return Promise.resolve(this.wrap(results))
	}

	run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
		const changes = this.db.query<T, SQLQueryBindings[]>(this.sql).run(...this.params)
		const result = this.wrap<T>([])
		result.meta.changes = changes.changes
		return Promise.resolve(result)
	}

	raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>
	raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>
	raw<T = unknown[]>(_options?: { columnNames?: boolean }): Promise<T[] | [string[], ...T[]]> {
		throw new Error('raw() is not used by Db and is not implemented in the test adapter')
	}

	private wrap<T>(results: T[]): D1Result<T> {
		return {
			results,
			success: true,
			meta: {
				duration: 0,
				size_after: 0,
				rows_read: 0,
				rows_written: 0,
				last_row_id: 0,
				changed_db: false,
				changes: 0,
			},
		}
	}
}

class TestD1Database implements D1Database {
	constructor(private readonly db: Database) {}

	prepare(query: string): D1PreparedStatement {
		return new TestD1PreparedStatement(this.db, query)
	}

	async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
		const out: D1Result<T>[] = []
		this.db.run('BEGIN')
		try {
			for (const stmt of statements) {
				out.push(await stmt.all<T>())
			}
			this.db.run('COMMIT')
		} catch (err) {
			this.db.run('ROLLBACK')
			throw err
		}
		return out
	}

	exec(_query: string): Promise<D1ExecResult> {
		throw new Error('exec() is not used by Db and is not implemented in the test adapter')
	}

	withSession(_constraintOrBookmark?: string): D1DatabaseSession {
		throw new Error('withSession() is not used by Db and is not implemented in the test adapter')
	}

	dump(): Promise<ArrayBuffer> {
		throw new Error('dump() is not used by Db and is not implemented in the test adapter')
	}
}

/**
 * Narrow a single result row to one named column. `Db` never calls `first(colName)`
 * (it always reads whole rows), so this path is unexercised by these tests; it
 * exists only to satisfy the D1 overload. Kept honest (no `as`) via an unknown
 * JSON round-trip into the generic.
 */
function pluck<T>(row: T, colName: string): T | null {
	const box: { v: unknown } = { v: row }
	const reread: { v: Record<string, unknown> } = JSON.parse(JSON.stringify(box))
	const value: unknown = reread.v[colName]
	if (value === undefined || value === null) {
		return null
	}
	const out: { v: T } = JSON.parse(JSON.stringify({ v: value }))
	return out.v
}

/** Coerce a bound value into a bun:sqlite-acceptable binding (no `as`). */
function toBinding(value: unknown): SQLQueryBindings {
	if (
		value === null
		|| typeof value === 'string'
		|| typeof value === 'number'
		|| typeof value === 'bigint'
		|| typeof value === 'boolean'
	) {
		return value
	}
	if (value === undefined) {
		return null
	}
	throw new Error(`unsupported bind value of type ${typeof value}`)
}

// ── DB + services assembly ────────────────────────────────────────────────────

const migration = allMigrations()

export interface Harness {
	/** Raw sqlite connection — seed rows directly with `.run(...)`. */
	sqlite: Database
	/** The production `Db` over the in-memory sqlite, via the D1 adapter. */
	db: Db
	signToken: typeof signToken
	/**
	 * Create an active SSO session for a principal and return the plaintext `px_session` cookie value
	 * (the native admin/auth credential). Mirrors what `/auth/callback` does after a successful login.
	 */
	signSession(principalId: string, options?: SignSessionOptions): Promise<string>
	/** Build a `Services` for the given environment + Access config. */
	makeServices(options?: MakeServicesOptions): Services
}

export interface SignSessionOptions {
	/** IdP `sub` recorded on the session row. */
	idpSub?: string
	/** Verified email recorded on the session row. */
	email?: string
	/** Absolute expiry (unix seconds); defaults to 1h out. */
	expiresAt?: number
}

export interface MakeServicesOptions {
	/** ENVIRONMENT value (e.g. 'local', 'stage'). Defaults to 'local'. */
	environment?: string
	/** ACCESS_APPS map. Defaults to {} (empty — the local-bypass precondition). */
	accessApps?: AccessApps
	/** IAM_BOOTSTRAP_ADMINS emails. Defaults to empty. */
	bootstrapAdmins?: ReadonlySet<string>
	/** Central human-admission allowlist. Defaults to `{ emailDomains: ['contember.com'], emails: [] }`. */
	human?: { emailDomains?: readonly string[]; emails?: readonly string[] }
	/** Cloudflare Access surface. Defaults to a fresh in-memory `FakeCfAccess`. */
	cfAccess?: CfAccess
	/** OIDC client. Defaults to one with injected (offline) discovery metadata; tests override for the callback flow. */
	oidc?: OidcClient
	/** propustka's own origin (token `iss` + OIDC redirect base). */
	issuer?: string
	/** SSO session cookie `Domain`; empty = host-only. */
	sessionCookieDomain?: string
}

/** Stand up a fresh in-memory DB + helpers. Call once per test for isolation. */
export function createHarness(): Harness {
	const sqlite = new Database(':memory:')
	sqlite.exec('PRAGMA foreign_keys = ON')
	sqlite.exec(migration)
	const db = new Db(new TestD1Database(sqlite))
	const identity = new IdentityClient()

	function makeServices(options: MakeServicesOptions = {}): Services {
		const accessApps = options.accessApps ?? {}
		const issuer = options.issuer ?? 'http://localhost:18191'
		const config: Config = {
			accessApps,
			team: TEAM,
			human: {
				emailDomains: options.human?.emailDomains ?? ['contember.com'],
				emails: options.human?.emails ?? [],
			},
			bootstrapAdmins: options.bootstrapAdmins ?? new Set(),
			cfApiToken: '',
			cfAccountId: '',
			environment: options.environment ?? 'local',
			issuer,
			sessionCookieDomain: options.sessionCookieDomain ?? '',
		}
		return {
			db,
			jwt: new JwtValidator(TEAM, accessApps, localJwks),
			identity,
			cfAccess: options.cfAccess ?? new FakeCfAccess(),
			oidc: options.oidc ?? new OidcClient(
				{
					issuer: 'https://idp.test',
					clientId: 'dummy',
					clientSecret: 'dummy',
					redirectUri: `${issuer}/auth/callback`,
					scopes: '',
					requireVerifiedEmail: true,
				},
				{ metadata: HARNESS_OIDC_METADATA },
			),
			config,
		}
	}

	async function signSession(principalId: string, options: SignSessionOptions = {}): Promise<string> {
		const token = nextId('sess')
		await db.createSession({
			tokenHash: await hashToken(token),
			principalId,
			idpSub: options.idpSub ?? `idp-${principalId}`,
			email: options.email ?? 'admin@example.com',
			expiresAt: options.expiresAt ?? Math.floor(Date.now() / 1000) + 3600,
		})
		return token
	}

	return { sqlite, db, signToken, signSession, makeServices }
}

// ── Seeding helpers (direct INSERTs against the real schema) ──────────────────

let seq = 0
function nextId(prefix: string): string {
	seq += 1
	return `${prefix}-${seq}`
}

export interface SeedUserOptions {
	/** Access `sub`. Null → an unclaimed invite. */
	sub?: string | null
	email: string
	label?: string
	disabled?: boolean
}

/** Insert a user principal; returns its id. */
export function seedUser(sqlite: Database, options: SeedUserOptions): string {
	const id = nextId('user')
	sqlite.run(
		'INSERT INTO principals (id, type, external_id, email, label, disabled_at) VALUES (?, ?, ?, ?, ?, ?)',
		[
			id,
			'user',
			options.sub ?? null,
			options.email,
			options.label ?? options.email,
			options.disabled ? 1 : null,
		],
	)
	return id
}

export interface SeedServiceOptions {
	/** Access `common_name` (the service token Client ID). */
	commonName: string
	label?: string
	disabled?: boolean
}

/** Insert a service principal; returns its id. */
export function seedService(sqlite: Database, options: SeedServiceOptions): string {
	const id = nextId('svc')
	sqlite.run(
		'INSERT INTO principals (id, type, external_id, email, label, disabled_at) VALUES (?, ?, ?, ?, ?, ?)',
		[id, 'service', options.commonName, null, options.label ?? options.commonName, options.disabled ? 1 : null],
	)
	return id
}

/** A flat scope coordinate for seeding ({ type, value }); null = global. */
export interface SeedScope {
	type: string
	value: string
}

/**
 * Insert a ROLE-BASED grant for a principal; returns its id. `scope` null → global,
 * `app` null → all apps (cross-app). The grant carries a named `roleKey` (the common
 * case in these tests); use `seedInlineGrant` for an inline action-pattern set.
 */
export function seedGrant(
	sqlite: Database,
	principalId: string,
	roleKey: string,
	scope: SeedScope | null = null,
	app: string | null = null,
): string {
	const id = nextId('grant')
	sqlite.run(
		'INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value, app) VALUES (?, ?, ?, ?, ?, ?)',
		[id, principalId, roleKey, scope?.type ?? null, scope?.value ?? null, app],
	)
	return id
}

/** Insert an INLINE grant (an action-pattern set, no role) for a principal; returns its id. */
export function seedInlineGrant(
	sqlite: Database,
	principalId: string,
	permissions: string[],
	scope: SeedScope | null = null,
	app: string | null = null,
): string {
	const id = nextId('grant')
	sqlite.run(
		'INSERT INTO grants (id, principal_id, permissions, scope_type, scope_value, app) VALUES (?, ?, ?, ?, ?, ?)',
		[id, principalId, JSON.stringify(permissions), scope?.type ?? null, scope?.value ?? null, app],
	)
	return id
}

/** Insert a role row for an app (origin 'app' by default); returns its (app, role_key). */
export function seedRole(
	sqlite: Database,
	app: string,
	roleKey: string,
	permissions: string[],
	options: { name?: string; description?: string | null; origin?: 'app' | 'custom' } = {},
): void {
	sqlite.run(
		'INSERT INTO roles (app, role_key, name, description, permissions, origin) VALUES (?, ?, ?, ?, ?, ?)',
		[app, roleKey, options.name ?? roleKey, options.description ?? null, JSON.stringify(permissions), options.origin ?? 'app'],
	)
}

/** Insert an action-catalog row for an app. */
export function seedAppAction(sqlite: Database, app: string, action: string, description: string | null = null): void {
	sqlite.run('INSERT INTO app_actions (app, action, description) VALUES (?, ?, ?)', [app, action, description])
}

/** Insert a scope-dimension row for an app. */
export function seedAppScope(sqlite: Database, app: string, scopeType: string, label: string | null = null): void {
	sqlite.run('INSERT INTO app_scopes (app, scope_type, label) VALUES (?, ?, ?)', [app, scopeType, label])
}
