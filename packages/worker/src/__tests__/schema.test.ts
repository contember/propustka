import { Database } from 'bun:sqlite'
import { expect, test } from 'bun:test'
import { allMigrations } from './helpers/migrations'

// Apply the real migrations to an in-memory SQLite and assert the schema contract
// the Worker relies on: the table set, the partial unique indexes (the NULL-in-UNIQUE
// traps), the role/inline XOR + both-or-neither scope CHECKs, the atomic redeem
// UPDATE…RETURNING, and the json_valid CHECK on diff.

const migration = allMigrations()

function freshDb(): Database {
	const db = new Database(':memory:')
	db.exec('PRAGMA foreign_keys = ON')
	db.exec(migration)
	return db
}

test('creates every table the worker reads/writes (and retires projects)', () => {
	const db = freshDb()
	const rows = db.query<{ name: string }, []>("SELECT name FROM sqlite_master WHERE type = 'table'").all()
	const names = rows.map((r) => r.name)
	for (
		const t of [
			'principals',
			'app_scopes',
			'app_actions',
			'roles',
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
	// `projects` is gone — scope values are app-owned now, not a Propustka table.
	expect(names).not.toContain('projects')
})

test('roles.permissions rejects non-JSON via the json_valid CHECK', () => {
	const db = freshDb()
	expect(() => db.run("INSERT INTO roles (app, role_key, name, permissions, origin) VALUES ('opice', 'editor', 'Editor', 'not json', 'app')"))
		.toThrow()
	expect(() =>
		db.run("INSERT INTO roles (app, role_key, name, permissions, origin) VALUES ('opice', 'editor', 'Editor', '[\"project.read\"]', 'app')")
	).not.toThrow()
	// origin is constrained to the two known values.
	expect(() => db.run("INSERT INTO roles (app, role_key, name, permissions, origin) VALUES ('opice', 'viewer', 'Viewer', '[]', 'bogus')")).toThrow()
})

test('a grant must carry EITHER a role_key OR inline permissions — never both, never neither', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	// Both set — rejected.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, permissions) VALUES ('gb', 'p1', 'editor', '[\"project.read\"]')")).toThrow()
	// Neither set — rejected.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, permissions) VALUES ('gn', 'p1', NULL, NULL)")).toThrow()
	// Role-only — ok.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key) VALUES ('gr', 'p1', 'editor')")).not.toThrow()
	// Inline-only — ok.
	expect(() => db.run("INSERT INTO grants (id, principal_id, permissions) VALUES ('gi', 'p1', '[\"report.export\"]')")).not.toThrow()
})

test('grant scope is both-or-neither (scope_type and scope_value rise/fall together)', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	// Half-set scopes are rejected.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g1', 'p1', 'editor', 'team', NULL)"))
		.toThrow()
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g2', 'p1', 'editor', NULL, 'acme')"))
		.toThrow()
	// Both set, or both NULL (global) — ok.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g3', 'p1', 'editor', 'team', 'acme')")).not
		.toThrow()
})

test('partial unique index forbids a second GLOBAL role grant for the same (principal, role)', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g1', 'p1', 'editor', NULL, NULL)")
	// Second global role grant with the same (principal, role) — rejected despite NULL scope.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g2', 'p1', 'editor', NULL, NULL)")).toThrow()
})

test('two scoped role grants for the same (principal, role) on DIFFERENT scope values are allowed', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g1', 'p1', 'editor', 'organization', 'acme')")
	expect(() =>
		db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g2', 'p1', 'editor', 'organization', 'globex')")
	).not.toThrow()
	// …but the SAME scope value twice is rejected.
	expect(() =>
		db.run("INSERT INTO grants (id, principal_id, role_key, scope_type, scope_value) VALUES ('g3', 'p1', 'editor', 'organization', 'acme')")
	).toThrow()
})

test('inline grants are NOT constrained by the unique indexes — each is a distinct attachment', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	// Two identical inline grants (same principal, scope, app, permissions) — both allowed,
	// because the partial unique indexes only cover role_key IS NOT NULL.
	db.run(
		"INSERT INTO grants (id, principal_id, app, permissions, scope_type, scope_value) VALUES ('i1', 'p1', 'opice', '[\"report.export\"]', 'team', 'acme')",
	)
	expect(() =>
		db.run(
			"INSERT INTO grants (id, principal_id, app, permissions, scope_type, scope_value) VALUES ('i2', 'p1', 'opice', '[\"report.export\"]', 'team', 'acme')",
		)
	).not.toThrow()
})

test('the same GLOBAL role for DIFFERENT apps is allowed; the same app twice is rejected', () => {
	const db = freshDb()
	db.run("INSERT INTO principals (id, type, external_id, email, label) VALUES ('p1', 'user', 'sub1', 'a@x.cz', 'a@x.cz')")
	db.run("INSERT INTO grants (id, principal_id, role_key, app) VALUES ('g1', 'p1', 'editor', 'opice')")
	// Same (principal, role) for a different app — allowed (the app dimension differentiates).
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, app) VALUES ('g2', 'p1', 'editor', 'poplach')")).not.toThrow()
	// …but the same app twice is rejected.
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, app) VALUES ('g3', 'p1', 'editor', 'opice')")).toThrow()
	// A NULL-app (all-apps) grant collides with another NULL-app one (COALESCE folds NULL→'*').
	db.run("INSERT INTO grants (id, principal_id, role_key, app) VALUES ('g4', 'p1', 'viewer', NULL)")
	expect(() => db.run("INSERT INTO grants (id, principal_id, role_key, app) VALUES ('g5', 'p1', 'viewer', NULL)")).toThrow()
})

test('group_role_mappings: same role for DIFFERENT scope values allowed, same scope twice rejected', () => {
	const db = freshDb()
	db.run(
		"INSERT INTO group_role_mappings (id, provider, group_ref, role_key, app, scope_type, scope_value) VALUES ('m1', 'github', 'org/core', 'editor', 'opice', 'organization', 'acme')",
	)
	expect(() =>
		db.run(
			"INSERT INTO group_role_mappings (id, provider, group_ref, role_key, app, scope_type, scope_value) VALUES ('m2', 'github', 'org/core', 'editor', 'opice', 'organization', 'globex')",
		)
	).not.toThrow()
	expect(() =>
		db.run(
			"INSERT INTO group_role_mappings (id, provider, group_ref, role_key, app, scope_type, scope_value) VALUES ('m3', 'github', 'org/core', 'editor', 'opice', 'organization', 'acme')",
		)
	).toThrow()
	// Mapping scope is also both-or-neither.
	expect(() =>
		db.run(
			"INSERT INTO group_role_mappings (id, provider, group_ref, role_key, scope_type, scope_value) VALUES ('m4', 'github', 'org/core', 'editor', 'team', NULL)",
		)
	).toThrow()
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
