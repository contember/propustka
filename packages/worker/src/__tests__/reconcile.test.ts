import { describe, expect, test } from 'bun:test'
import { createHarness } from './helpers/harness'

// The app-schema reconcile contract (db.reconcileAppSchema), driven through the real
// `Db` over the production migration. The load-bearing properties:
//   - it's idempotent and additive-then-pruning: a second reconcile with fewer items
//     removes the absent origin='app' rows;
//   - origin='custom' policies are NEVER touched by a reconcile (admin-composed
//     policies survive a redeploy that drops the app role they happen to share a key
//     space with);
//   - scopes/actions reconcile the same way (upsert + prune by the incoming set).

describe('Db.reconcileAppSchema', () => {
	test('upserts scopes, actions and origin=app roles, then prunes absent ones', async () => {
		const h = createHarness()
		const app = 'opice'

		await h.db.reconcileAppSchema({
			app,
			scopes: [{ scopeType: 'organization', label: 'Organization' }, { scopeType: 'team', label: null }],
			actions: [{ action: 'project.read', description: null }, { action: 'project.write', description: 'Edit' }],
			roles: [{ roleKey: 'editor', name: 'Editor', description: null, permissions: ['project.read', 'project.write'] }],
		})

		expect((await h.db.listAppScopes(app)).map((s) => s.scope_type)).toEqual(['organization', 'team'])
		expect(await h.db.listActionCatalog(app)).toEqual(['project.read', 'project.write'])
		expect((await h.db.listRolesByOrigin(app, 'app')).map((r) => r.role_key)).toEqual(['editor'])

		// Second reconcile: drop the 'team' scope, the 'project.write' action and add a
		// 'viewer' role while removing 'editor'. The absent origin='app' rows are pruned.
		await h.db.reconcileAppSchema({
			app,
			scopes: [{ scopeType: 'organization', label: 'Org (renamed)' }],
			actions: [{ action: 'project.read', description: null }],
			roles: [{ roleKey: 'viewer', name: 'Viewer', description: null, permissions: ['project.read'] }],
		})

		expect((await h.db.listAppScopes(app)).map((s) => s.scope_type)).toEqual(['organization'])
		// The label was updated in place (upsert), not duplicated.
		expect((await h.db.listAppScopes(app))[0]?.label).toBe('Org (renamed)')
		expect(await h.db.listActionCatalog(app)).toEqual(['project.read'])
		expect((await h.db.listRolesByOrigin(app, 'app')).map((r) => r.role_key)).toEqual(['viewer'])
	})

	test('a reconcile NEVER touches origin=custom policies', async () => {
		const h = createHarness()
		const app = 'opice'

		// First reconcile seeds the action catalog + an app role.
		await h.db.reconcileAppSchema({
			app,
			scopes: [],
			actions: [{ action: 'report.read', description: null }, { action: 'report.export', description: null }],
			roles: [{ roleKey: 'editor', name: 'Editor', description: null, permissions: ['report.read'] }],
		})

		// An admin composes a custom policy (origin='custom').
		await h.db.upsertRole({
			app,
			roleKey: 'auditor',
			name: 'Auditor',
			description: 'Read + export',
			permissions: ['report.read', 'report.export'],
			origin: 'custom',
		})

		// A second reconcile that drops the 'editor' app role entirely. The custom
		// 'auditor' policy must survive untouched.
		await h.db.reconcileAppSchema({
			app,
			scopes: [],
			actions: [{ action: 'report.read', description: null }, { action: 'report.export', description: null }],
			roles: [],
		})

		expect((await h.db.listRolesByOrigin(app, 'app')).map((r) => r.role_key)).toEqual([])
		const custom = await h.db.listRolesByOrigin(app, 'custom')
		expect(custom.map((r) => r.role_key)).toEqual(['auditor'])
		const auditor = await h.db.getRole(app, 'auditor')
		expect(auditor?.origin).toBe('custom')
		expect(auditor?.name).toBe('Auditor')
	})

	test('reconciling with empty sets prunes all the app rows (but not custom policies)', async () => {
		const h = createHarness()
		const app = 'poplach'

		await h.db.reconcileAppSchema({
			app,
			scopes: [{ scopeType: 'project', label: null }],
			actions: [{ action: 'project.read', description: null }],
			roles: [{ roleKey: 'editor', name: 'Editor', description: null, permissions: ['project.read'] }],
		})
		await h.db.upsertRole({ app, roleKey: 'custom1', name: 'C1', permissions: ['project.read'], origin: 'custom' })

		await h.db.reconcileAppSchema({ app, scopes: [], actions: [], roles: [] })

		expect(await h.db.listAppScopes(app)).toHaveLength(0)
		expect(await h.db.listActionCatalog(app)).toHaveLength(0)
		expect(await h.db.listRolesByOrigin(app, 'app')).toHaveLength(0)
		// The custom policy is preserved even though its permissions now reference an
		// action no longer in the catalog (validation is at write time, not prune time).
		expect((await h.db.listRolesByOrigin(app, 'custom')).map((r) => r.role_key)).toEqual(['custom1'])
	})

	test('an app role is isolated to its app (no cross-app bleed)', async () => {
		const h = createHarness()
		await h.db.reconcileAppSchema({
			app: 'opice',
			scopes: [],
			actions: [{ action: 'a.read', description: null }],
			roles: [{ roleKey: 'editor', name: 'Editor', description: null, permissions: ['a.read'] }],
		})
		// A different app's reconcile leaves opice's roles intact.
		await h.db.reconcileAppSchema({
			app: 'poplach',
			scopes: [],
			actions: [{ action: 'b.read', description: null }],
			roles: [{ roleKey: 'editor', name: 'Editor', description: null, permissions: ['b.read'] }],
		})
		expect((await h.db.listRoles('opice')).map((r) => r.role_key)).toEqual(['editor'])
		expect((await h.db.getRole('opice', 'editor'))?.permissions).toBe(JSON.stringify(['a.read']))
		expect((await h.db.getRole('poplach', 'editor'))?.permissions).toBe(JSON.stringify(['b.read']))
	})
})
