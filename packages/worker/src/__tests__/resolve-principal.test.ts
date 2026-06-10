import { describe, expect, test } from 'bun:test'
import type { PrincipalRow } from '../db'
import { resolveUserPrincipal, type UserPrincipalStore } from '../resolve'

// Minimal in-memory stand-in for the store resolveUserPrincipal touches. Keeps the
// test pure (no D1) while exercising the real 3-step claim-then-lazy logic. Declared
// `implements UserPrincipalStore` so it satisfies the contract with no `as` cast.
class FakeStore implements UserPrincipalStore {
	rows: PrincipalRow[] = []

	private user(predicate: (r: PrincipalRow) => boolean): PrincipalRow | null {
		return this.rows.find((r) => r.type === 'user' && predicate(r)) ?? null
	}

	getUserByExternalId(sub: string): Promise<PrincipalRow | null> {
		return Promise.resolve(this.user((r) => r.external_id === sub))
	}

	getUserByEmail(email: string): Promise<PrincipalRow | null> {
		return Promise.resolve(this.user((r) => r.email === email))
	}

	refreshUserLabel(id: string, email: string): Promise<void> {
		const row = this.rows.find((r) => r.id === id)
		if (row) {
			row.email = email
			row.label = email
		}
		return Promise.resolve()
	}

	claimInvitedUser(id: string, sub: string, email: string): Promise<PrincipalRow | null> {
		const row = this.rows.find((r) => r.id === id && r.external_id === null)
		if (!row) {
			return Promise.resolve(null)
		}
		row.external_id = sub
		row.label = email
		return Promise.resolve(row)
	}

	createUser(sub: string, email: string): Promise<PrincipalRow> {
		const row: PrincipalRow = {
			id: `u-${sub}`,
			type: 'user',
			external_id: sub,
			email,
			label: email,
			disabled_at: null,
			created_at: 0,
		}
		this.rows.push(row)
		return Promise.resolve(row)
	}
}

const invited = (email: string): PrincipalRow => ({
	id: `inv-${email}`,
	type: 'user',
	external_id: null,
	email,
	label: email,
	disabled_at: null,
	created_at: 0,
})

describe('resolveUserPrincipal (3-step claim-then-lazy)', () => {
	test('1. resolves a returning user by sub', async () => {
		const db = new FakeStore()
		db.rows.push({ id: 'p1', type: 'user', external_id: 'sub-1', email: 'a@x.com', label: 'a@x.com', disabled_at: null, created_at: 0 })
		const res = await resolveUserPrincipal(db, 'sub-1', 'a@x.com')
		expect(res.ok).toBe(true)
		if (res.ok) {
			expect(res.principal.id).toBe('p1')
		}
	})

	test('1. updates label when the token email changed (identity stays keyed by sub)', async () => {
		const db = new FakeStore()
		db.rows.push({ id: 'p1', type: 'user', external_id: 'sub-1', email: 'old@x.com', label: 'old@x.com', disabled_at: null, created_at: 0 })
		const res = await resolveUserPrincipal(db, 'sub-1', 'new@x.com')
		expect(res.ok).toBe(true)
		if (res.ok) {
			expect(res.principal.id).toBe('p1')
			expect(res.principal.label).toBe('new@x.com')
		}
		// Identity is still the same row — grants/audit keyed by id, not email.
		expect(db.rows).toHaveLength(1)
	})

	test('disabled returning user → disabled', async () => {
		const db = new FakeStore()
		db.rows.push({ id: 'p1', type: 'user', external_id: 'sub-1', email: 'a@x.com', label: 'a@x.com', disabled_at: 123, created_at: 0 })
		const res = await resolveUserPrincipal(db, 'sub-1', 'a@x.com')
		expect(res).toEqual({ ok: false, reason: 'disabled' })
	})

	test('2. claims an invited row by verified email and binds the sub', async () => {
		const db = new FakeStore()
		db.rows.push(invited('invitee@x.com'))
		const res = await resolveUserPrincipal(db, 'sub-new', 'invitee@x.com')
		expect(res.ok).toBe(true)
		if (res.ok) {
			expect(res.principal.external_id).toBe('sub-new')
			expect(res.principal.id).toBe('inv-invitee@x.com') // pre-created id kept → pre-created grants apply
		}
	})

	test('3. lazy-creates when neither sub nor email match', async () => {
		const db = new FakeStore()
		const res = await resolveUserPrincipal(db, 'sub-x', 'fresh@x.com')
		expect(res.ok).toBe(true)
		if (res.ok) {
			expect(res.principal.external_id).toBe('sub-x')
			expect(res.principal.email).toBe('fresh@x.com')
		}
		expect(db.rows).toHaveLength(1)
	})

	test('email already claimed by a different sub → unknown_principal (fail closed, no insert)', async () => {
		const db = new FakeStore()
		db.rows.push({ id: 'p1', type: 'user', external_id: 'sub-owner', email: 'shared@x.com', label: 'shared@x.com', disabled_at: null, created_at: 0 })
		const res = await resolveUserPrincipal(db, 'sub-other', 'shared@x.com')
		expect(res).toEqual({ ok: false, reason: 'unknown_principal' })
		// No second user was created.
		expect(db.rows).toHaveLength(1)
	})
})
