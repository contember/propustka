import { Database } from 'bun:sqlite'
import { expect, test } from 'bun:test'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { normalizeGroupRef } from '../identity'

// CORR-2: store-time normalization must be symmetric with resolution. `createGroupMapping`
// persists the admin-supplied ref NORMALIZED (lowercased/trimmed `<org>/<team>` via
// `normalizeGroupRef`, provider lowercased). Resolution then matches via the exact SQL
// `provider = ? AND group_ref IN (...)` with refs that come from `normalizeGroupRef` too,
// so a mixed-case admin input must match a lowercased identity ref + provider `github`.
//
// The handler itself needs the full Worker context (auth/services); we cannot import it in
// isolation, so we replicate its exact normalization steps and the db layer's lookup SQL
// against the real migration (the schema.test.ts bun:sqlite pattern) to prove the contract.

const migration = readFileSync(join(import.meta.dir, '..', '..', 'migrations', '0001_init.sql'), 'utf8')

function freshDb(): Database {
	const db = new Database(':memory:')
	db.exec('PRAGMA foreign_keys = ON')
	db.exec(migration)
	return db
}

// Mirror the store-time normalization performed by `createGroupMapping` in admin/handlers.ts.
function normalizeMappingInput(provider: string, groupRef: string): { provider: string; groupRef: string } {
	const slash = groupRef.indexOf('/')
	const org = groupRef.slice(0, slash).trim()
	const team = groupRef.slice(slash + 1).trim()
	return { provider: provider.trim().toLowerCase(), groupRef: normalizeGroupRef(org, team) }
}

test('mixed-case admin input is stored so it matches a lowercased identity ref + provider github', () => {
	const db = freshDb()

	// Admin supplies a display-cased org/team and provider, as the UI passes them through.
	const stored = normalizeMappingInput('GitHub', 'My-Org/Core-Devs')
	db.run(
		"INSERT INTO group_role_mappings (id, provider, group_ref, role_key) VALUES ('m1', ?, ?, 'editor')",
		[stored.provider, stored.groupRef],
	)

	// Resolution looks the mapping up with the provider constant `github` and identity refs
	// that `parseGroupRefs` produced via `normalizeGroupRef` — i.e. already lowercased.
	const identityRef = normalizeGroupRef('My-Org', 'Core-Devs') // 'my-org/core-devs'
	const match = db
		.query<{ id: string }, [string, string]>(
			'SELECT id FROM group_role_mappings WHERE provider = ? AND group_ref IN (?)',
		)
		.get('github', identityRef)

	expect(stored.provider).toBe('github')
	expect(stored.groupRef).toBe('my-org/core-devs')
	expect(match?.id).toBe('m1')
})

test('a ref stored verbatim (the bug) would NOT match the normalized lookup', () => {
	const db = freshDb()
	// The pre-fix behaviour: store provider/groupRef exactly as typed.
	db.run("INSERT INTO group_role_mappings (id, provider, group_ref, role_key) VALUES ('m1', 'GitHub', 'My-Org/Core-Devs', 'editor')")

	const identityRef = normalizeGroupRef('My-Org', 'Core-Devs')
	const match = db
		.query<{ id: string }, [string, string]>(
			'SELECT id FROM group_role_mappings WHERE provider = ? AND group_ref IN (?)',
		)
		.get('github', identityRef)

	// Confirms the finding: a verbatim row silently confers zero permissions.
	expect(match).toBeNull()
})

test('normalization trims whitespace around org and team', () => {
	const stored = normalizeMappingInput('  GitHub  ', ' Acme / Platform ')
	expect(stored.provider).toBe('github')
	expect(stored.groupRef).toBe('acme/platform')
})
