import { Database } from 'bun:sqlite'
import { expect, test } from 'bun:test'
import { allMigrations } from './helpers/migrations'

// Apply the real migrations to an in-memory SQLite and assert the schema contract
// the Worker relies on: the table set, the partial unique indexes (the NULL-in-UNIQUE
// traps), the atomic redeem UPDATE…RETURNING, and the json_valid CHECK on diff.

const migration = allMigrations()

function freshDb(): Database {
	const db = new Database(':memory:')
	db.exec('PRAGMA foreign_keys = ON')
	db.exec(migration)
	return db
}

test('creates every table the worker reads/writes', () => {
	const db = freshDb()
	const rows = db.query<{ name: string }, []>("SELECT name FROM sqlite_master WHERE type = 'table'").all()
	const names = rows.map((r) => r.name)
	for (
		const t of [
			'principals',
			'projects',
			'grants',
			'group_role_mappings',
			'audit_events',
			'auth_log',
			'capability_tokens',
			'capability_grants',
		]
	) {
		expect(names).toContain(t)
	}
})

test('partial unique index forbids a second GLOBAL grant for the same (principal, role)', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	db.run("INSERT INTO grants (id, principal_id, role_key, project_id) VALUES ('g1', 'p1', 'editor', NULL)")
	// Second global grant with the same (principal, role) — must be rejected despite NULL project_id.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, project_id) VALUES ('g2', 'p1', 'editor', NULL)")).toThrow()
})

test('two project-scoped grants for the same (principal, role) on DIFFERENT projects are allowed', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	db.run("INSERT INTO projects (id, slug, name) VALUES ('pr1', 'alpha', 'Alpha'), ('pr2', 'beta', 'Beta')")
	db.run("INSERT INTO grants (id, principal_id, role_key, project_id) VALUES ('g1', 'p1', 'editor', 'pr1')")
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, project_id) VALUES ('g2', 'p1', 'editor', 'pr2')")).not.toThrow()
	// …but the SAME project twice is rejected.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, project_id) VALUES ('g3', 'p1', 'editor', 'pr1')")).toThrow()
})

test('the same GLOBAL role for DIFFERENT apps is allowed; the same app twice is rejected', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	db.run("INSERT INTO grants (id, principal_id, role_key, project_id, app) VALUES ('g1', 'p1', 'editor', NULL, 'opice')")
	// Same (principal, role) for a different app — allowed (the app dimension differentiates).
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, project_id, app) VALUES ('g2', 'p1', 'editor', NULL, 'poplach')")).not.toThrow()
	// …but the same app twice is rejected.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, project_id, app) VALUES ('g3', 'p1', 'editor', NULL, 'opice')")).toThrow()
	// A NULL-app (all-apps) grant collides with another NULL-app one (COALESCE folds NULL→'*').
	db.run("INSERT INTO grants (id, principal_id, role_key, project_id, app) VALUES ('g4', 'p1', 'viewer', NULL, NULL)")
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, project_id, app) VALUES ('g5', 'p1', 'viewer', NULL, NULL)")).toThrow()
})

test('at most one user principal per email (invite target uniqueness)', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', NULL, 'dup@x.cz', 'dup@x.cz')")
	expect(() => db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p2', 'user', NULL, 'dup@x.cz', 'dup@x.cz')")).toThrow()
})

test('atomic redeem UPDATE…RETURNING increments used_count and returns the token', () => {
	const db = freshDb()
	db.run(
		"INSERT INTO capability_tokens (id, token_hash, label, max_uses, used_count) VALUES ('t1', 'hash1', 'Share Q2', 3, 0)",
	)
	const redeem = db.query<{ id: string; label: string | null }, [string]>(
		`UPDATE capability_tokens SET used_count = used_count + 1
		 WHERE token_hash = ?
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > unixepoch())
		   AND (max_uses IS NULL OR used_count < max_uses)
		 RETURNING id, label`,
	)
	const first = redeem.get('hash1')
	expect(first?.id).toBe('t1')
	const after = db.query<{ used_count: number }, [string]>('SELECT used_count FROM capability_tokens WHERE id = ?').get('t1')
	expect(after?.used_count).toBe(1)
})

test('redeem matches zero rows when revoked / expired / exhausted', () => {
	const db = freshDb()
	const stmt = db.query<{ id: string }, [string]>(
		`UPDATE capability_tokens SET used_count = used_count + 1
		 WHERE token_hash = ?
		   AND revoked_at IS NULL
		   AND (expires_at IS NULL OR expires_at > unixepoch())
		   AND (max_uses IS NULL OR used_count < max_uses)
		 RETURNING id`,
	)
	db.run("INSERT INTO capability_tokens (id, token_hash, revoked_at) VALUES ('rev', 'hRev', unixepoch())")
	db.run("INSERT INTO capability_tokens (id, token_hash, expires_at) VALUES ('exp', 'hExp', unixepoch() - 1)")
	db.run("INSERT INTO capability_tokens (id, token_hash, max_uses, used_count) VALUES ('exh', 'hExh', 2, 2)")
	expect(stmt.get('hRev')).toBeNull()
	expect(stmt.get('hExp')).toBeNull()
	expect(stmt.get('hExh')).toBeNull()
	// A clean follow-up SELECT can still find the row to classify the failure.
	const row = db.query<{ revoked_at: number | null }, [string]>('SELECT revoked_at FROM capability_tokens WHERE token_hash = ?').get('hRev')
	expect(row?.revoked_at).not.toBeNull()
})

test('audit_events.diff rejects non-JSON via the json_valid CHECK', () => {
	const db = freshDb()
	const insert = (diff: string) =>
		db.run(
			`INSERT INTO audit_events (id, request_id, principal_label, app, action, resource_type, diff)
			 VALUES ('a1', 'r1', 'a@x.cz', 'app', 'x.update', 'x', ${diff})`,
		)
	expect(() => insert("'not json'")).toThrow()
	expect(() =>
		db.run(
			`INSERT INTO audit_events (id, request_id, principal_label, app, action, resource_type, diff)
		 VALUES ('a2', 'r1', 'a@x.cz', 'app', 'x.update', 'x', '{"field":["old","new"]}')`,
		)
	).not.toThrow()
})
