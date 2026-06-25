import { Database } from 'bun:sqlite'
import { beforeEach, describe, expect, mock, test } from 'bun:test'
import { LOCAL_DEV_ADMIN_ID } from '../auth'
import type { Env } from '../env'
import { allMigrations } from './helpers/migrations'

// TEST-4: the RPC entrypoint (`Propustka` in src/index.ts) wires several spec-mandated
// behaviors that nothing else exercises:
//   1. every authenticate()/redeemCapability() writes EXACTLY ONE auth_log row with the
//      right app, decision (allow/deny) and reason;
//   2. issueCapability resolves the issuer server-side and its `iam.capability.create`
//      audit event carries the grants but NEVER the plaintext token.
//
// We drive the real class against a real `Db(env.DB)` backed by an in-memory bun:sqlite
// (the schema.test.ts pattern), seeding the `local-dev-admin` principal so auth-log /
// audit FK lookups resolve. We only ever pass `token: null`, so the JwtValidator returns
// `missing_token` synchronously and no JWKS network call is made — and ENVIRONMENT='local'
// + ACCESS_APPS='{}' lets the local-dev bypass resolve the global-admin issuer.

// `Propustka` extends `WorkerEntrypoint` from 'cloudflare:workers', which bun's test
// runtime cannot resolve. Stub it with a base class that just assigns ctx/env — exactly
// what the real WorkerEntrypoint does for our purposes. This is test infrastructure, not
// a source change: it must run BEFORE importing the class under test.
mock.module('cloudflare:workers', () => ({
	WorkerEntrypoint: class<E> {
		constructor(public readonly ctx: ExecutionContext, public readonly env: E) {}
	},
}))

const { Propustka } = await import('../index')

const migration = allMigrations()

// ── bun:sqlite → minimal D1Database adapter ───────────────────────────────────
// The `Db` class only uses prepare().bind().{first,all,run} and db.batch(...). We wrap
// a bun:sqlite Database in just enough of the D1 surface to satisfy that, with no casts.

class SqliteStatement implements D1PreparedStatement {
	constructor(private readonly db: Database, private readonly sql: string, private readonly args: unknown[] = []) {}

	bind(...values: unknown[]): D1PreparedStatement {
		return new SqliteStatement(this.db, this.sql, values)
	}

	first<T = unknown>(colName?: string): Promise<T | null> {
		const row = this.db.query(this.sql).get(...this.bindArgs())
		if (row === null) {
			return Promise.resolve(null)
		}
		if (colName !== undefined) {
			const value = (row as Record<string, unknown>)[colName]
			return Promise.resolve((value ?? null) as T | null)
		}
		return Promise.resolve(row as T)
	}

	run<T = Record<string, unknown>>(): Promise<D1Result<T>> {
		const res = this.db.query(this.sql).run(...this.bindArgs())
		return Promise.resolve(this.result<T>([], res.changes, res.lastInsertRowid))
	}

	all<T = Record<string, unknown>>(): Promise<D1Result<T>> {
		const rows = this.db.query(this.sql).all(...this.bindArgs()) as T[]
		return Promise.resolve(this.result<T>(rows))
	}

	// `Db` never calls raw(); declared only to satisfy the D1PreparedStatement contract.
	raw<T = unknown[]>(options: { columnNames: true }): Promise<[string[], ...T[]]>
	raw<T = unknown[]>(options?: { columnNames?: false }): Promise<T[]>
	raw(): Promise<unknown[]> {
		throw new Error('raw() not supported in the test D1 adapter')
	}

	private bindArgs(): (string | number | bigint | boolean | null)[] {
		return this.args.map((a) => {
			if (a === null || typeof a === 'string' || typeof a === 'number' || typeof a === 'bigint' || typeof a === 'boolean') {
				return a
			}
			throw new Error(`unsupported bind value: ${String(a)}`)
		})
	}

	private result<T>(results: T[], changes = 0, lastRowId: number | bigint = 0): D1Result<T> {
		return {
			results,
			success: true,
			meta: {
				duration: 0,
				size_after: 0,
				rows_read: results.length,
				rows_written: changes,
				last_row_id: Number(lastRowId),
				changed_db: changes > 0,
				changes,
			},
		}
	}
}

class SqliteD1 implements D1Database {
	constructor(private readonly db: Database) {}

	prepare(query: string): D1PreparedStatement {
		return new SqliteStatement(this.db, query)
	}

	async batch<T = unknown>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> {
		const out: D1Result<T>[] = []
		for (const s of statements) {
			out.push(await s.run<T>())
		}
		return out
	}

	async exec(query: string): Promise<D1ExecResult> {
		this.db.exec(query)
		return { count: 0, duration: 0 }
	}

	dump(): Promise<ArrayBuffer> {
		throw new Error('dump() not supported in the test D1 adapter')
	}

	withSession(): D1DatabaseSession {
		throw new Error('withSession() not supported in the test D1 adapter')
	}
}

// ── Test fixtures ──────────────────────────────────────────────────────────────

// An ASSETS Fetcher we never call on the RPC paths under test.
const assetsStub: Fetcher = {
	fetch() {
		throw new Error('ASSETS.fetch must not be called on the RPC paths under test')
	},
	connect() {
		throw new Error('ASSETS.connect must not be called')
	},
} as unknown as Fetcher

function freshDb(): Database {
	const db = new Database(':memory:')
	db.exec('PRAGMA foreign_keys = ON')
	db.exec(migration)
	// Seed the local-dev-admin principal so auth_log / audit_events FK lookups resolve.
	db.run(
		"INSERT INTO principals (id, type, external_id, email, label) VALUES (?, 'user', ?, 'admin@local.test', 'local-dev-admin')",
		[LOCAL_DEV_ADMIN_ID, LOCAL_DEV_ADMIN_ID],
	)
	return db
}

function makeEnv(db: Database, overrides: Partial<Pick<Env, 'ACCESS_APPS' | 'ENVIRONMENT'>> = {}): Env {
	return {
		DB: new SqliteD1(db),
		ASSETS: assetsStub,
		ACCESS_APPS: overrides.ACCESS_APPS ?? '{}',
		TEAM: 'https://test.cloudflareaccess.com',
		HUMAN_EMAIL_DOMAINS: '["contember.com"]',
		HUMAN_EMAILS: '[]',
		IAM_BOOTSTRAP_ADMINS: '[]',
		CF_API_TOKEN: 'dummy-token',
		CF_ACCOUNT_ID: 'dummy-account',
		ENVIRONMENT: overrides.ENVIRONMENT ?? 'local',
		ISSUER: 'http://localhost:18191',
		PROPUSTKA_SIGNING_KEYS: '',
		SESSION_COOKIE_DOMAIN: '',
		OIDC_ISSUER: 'https://idp.test',
		OIDC_CLIENT_ID: '',
		OIDC_CLIENT_SECRET: 'dummy-oidc-secret',
		OIDC_SCOPES: '',
		OIDC_REQUIRE_VERIFIED_EMAIL: 'true',
	}
}

// A fake ExecutionContext that records the fire-and-forget promises so we can await
// them before querying the DB (all of Propustka's DB writes go through this.ctx.waitUntil).
interface FakeCtx extends ExecutionContext {
	promises: Promise<unknown>[]
}

function makeCtx(): FakeCtx {
	const promises: Promise<unknown>[] = []
	return {
		promises,
		waitUntil(p: Promise<unknown>): void {
			promises.push(p)
		},
		passThroughOnException(): void {},
		props: {},
	}
}

async function settle(ctx: FakeCtx): Promise<void> {
	await Promise.all(ctx.promises)
}

interface AuthLogRow {
	request_id: string
	app: string
	kind: string
	principal_id: string | null
	capability_token_id: string | null
	decision: string
	reason: string | null
}

function authLogRows(db: Database): AuthLogRow[] {
	return db.query<AuthLogRow, []>('SELECT * FROM auth_log').all()
}

interface AuditRow {
	id: string
	request_id: string
	principal_id: string | null
	principal_label: string
	app: string
	action: string
	resource_type: string
	resource_id: string | null
	diff: string | null
	metadata: string | null
}

function auditRows(db: Database): AuditRow[] {
	return db.query<AuditRow, []>('SELECT * FROM audit_events').all()
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe('Propustka RPC entrypoint (TEST-4)', () => {
	let db: Database

	beforeEach(() => {
		db = freshDb()
	})

	test('authenticate ALLOW writes one local-bypass auth_log row', async () => {
		// ENVIRONMENT='local' + ACCESS_APPS='{}' + token null → local dev bypass fires.
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db))

		const result = await worker.authenticate({ app: 'app-projects', token: null, cookie: null, origin: null, requestId: 'req-allow' })
		expect(result.ok).toBe(true)

		await settle(ctx)

		const rows = authLogRows(db)
		expect(rows).toHaveLength(1)
		const row = rows[0]
		expect(row?.kind).toBe('authenticate')
		expect(row?.decision).toBe('allow')
		expect(row?.principal_id).toBe(LOCAL_DEV_ADMIN_ID)
		expect(row?.reason).toBe('local_bypass')
		expect(row?.app).toBe('app-projects')
	})

	test('authenticate DENY (missing_token) writes one deny auth_log row, principal null, self-asserted app', async () => {
		// Non-empty ACCESS_APPS means the local bypass is disabled; token null → missing_token.
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db, { ACCESS_APPS: '{"aud":"app"}' }))

		const result = await worker.authenticate({ app: 'app-projects', token: null, cookie: null, origin: null, requestId: 'req-deny' })
		expect(result).toEqual({ ok: false, reason: 'missing_token' })

		await settle(ctx)

		const rows = authLogRows(db)
		expect(rows).toHaveLength(1)
		const row = rows[0]
		expect(row?.kind).toBe('authenticate')
		expect(row?.decision).toBe('deny')
		expect(row?.reason).toBe('missing_token')
		expect(row?.principal_id).toBeNull()
		// No verified token, so the app column is the self-asserted input.app.
		expect(row?.app).toBe('app-projects')
	})

	test('redeemCapability DENY (unknown token) writes one redeem auth_log row, capability_token_id null', async () => {
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db))

		const result = await worker.redeemCapability({ app: 'reports', token: 'does-not-exist', requestId: 'req-redeem' })
		expect(result.ok).toBe(false)

		await settle(ctx)

		const rows = authLogRows(db)
		expect(rows).toHaveLength(1)
		const row = rows[0]
		expect(row?.kind).toBe('redeem')
		expect(row?.decision).toBe('deny')
		expect(row?.capability_token_id).toBeNull()
		expect(row?.principal_id).toBeNull()
		expect(row?.app).toBe('reports')
	})

	test('issueCapability happy path: one capability.create audit row carrying grants, never the plaintext token', async () => {
		// Local bypass resolves the issuer to the global-admin (permissions: [{ action: '*' }]),
		// so the requested grant is fully covered and a token is issued.
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db))

		const grants = [{ action: 'report.read', resource: 'r-1' }]
		const result = await worker.issueCapability({
			app: 'reports',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'req-issue',
			grants,
		})

		expect(result.ok).toBe(true)
		if (!result.ok) {
			throw new Error('expected issueCapability to succeed')
		}
		expect(typeof result.token).toBe('string')
		expect(result.token.length).toBeGreaterThan(0)
		expect(typeof result.id).toBe('string')

		await settle(ctx)

		const rows = auditRows(db)
		expect(rows).toHaveLength(1)
		const row = rows[0]
		expect(row?.action).toBe('iam.capability.create')
		expect(row?.resource_type).toBe('capability')
		expect(row?.resource_id).toBe(result.id)
		expect(row?.principal_id).toBe(LOCAL_DEV_ADMIN_ID)

		// metadata.grants must equal the requested grants (action + resource only).
		const metadata: unknown = JSON.parse(row?.metadata ?? 'null')
		expect(metadata).toMatchObject({ grants: [{ action: 'report.read', resource: 'r-1' }] })

		// The plaintext token must NEVER be persisted anywhere on the audit row.
		const serializedRow = JSON.stringify(row)
		expect(serializedRow).not.toContain(result.token)
	})

	test('revokeCapability: issue → revoke flips the token, audits the revoke, and the token no longer redeems', async () => {
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db))

		// Issue under the local-bypass admin so the grant is covered.
		const issued = await worker.issueCapability({
			app: 'reports',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'req-issue',
			grants: [{ action: 'report.read', resource: 'r-1' }],
		})
		if (!issued.ok) {
			throw new Error('expected issueCapability to succeed')
		}

		const revoked = await worker.revokeCapability({
			app: 'reports',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'req-revoke',
			tokenId: issued.id,
		})
		expect(revoked).toEqual({ ok: true, revoked: true })

		// Redeeming the revoked token now fails with reason 'revoked'.
		const redeem = await worker.redeemCapability({ app: 'reports', token: issued.token, requestId: 'req-redeem' })
		expect(redeem.ok).toBe(false)
		if (redeem.ok) {
			throw new Error('unreachable')
		}
		expect(redeem.reason).toBe('revoked')

		// A second revoke is idempotent.
		const again = await worker.revokeCapability({
			app: 'reports',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'req-revoke-2',
			tokenId: issued.id,
		})
		expect(again).toEqual({ ok: true, revoked: false })

		await settle(ctx)

		// Exactly one iam.capability.revoke audit row (the no-op second revoke writes none).
		const revokeRows = auditRows(db).filter((r) => r.action === 'iam.capability.revoke')
		expect(revokeRows).toHaveLength(1)
		expect(revokeRows[0]?.resource_id).toBe(issued.id)
		expect(revokeRows[0]?.principal_id).toBe(LOCAL_DEV_ADMIN_ID)
	})

	test('revokeCapability: unknown id → not_found', async () => {
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db))
		const result = await worker.revokeCapability({
			app: 'reports',
			token: null,
			cookie: null,
			origin: null,
			requestId: 'req-revoke-missing',
			tokenId: 'does-not-exist',
		})
		expect(result).toEqual({ ok: false, reason: 'not_found' })
	})

	test('listPrincipals: the app-less local-dev bypass (no verified app) is not_allowed', async () => {
		const ctx = makeCtx()
		const worker = new Propustka(ctx, makeEnv(db))
		// Local bypass resolves a global-admin caller but with NO aud-verified app — there is no
		// app to scope the roster to, so the read fails closed.
		const result = await worker.listPrincipals({ app: 'poplach', token: null, cookie: null, origin: null, requestId: 'req-list-local' })
		expect(result).toEqual({ ok: false, reason: 'not_allowed' })
	})
})
