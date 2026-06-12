import type { PermissionEntry, RoleDef, Scope } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import type { GrantRow, GroupMappingRow } from '../db'
import { computePermissions, type ResolutionInputs } from '../resolve'
import { makeRoleSource } from '../roles'

// computePermissions is PURE: it takes already-fetched rows plus an app-aware
// RoleSource (built-ins layered over the calling app's DB roles, loaded up front).
// These tests build that RoleSource from an in-memory role map and assert the union /
// expansion / dedup behavior across role grants, inline grants, groups and bootstrap.

const APP = 'opice'

// The app's DB roles for this suite (what the worker loads from the `roles` table).
const APP_ROLES: Record<string, RoleDef> = {
	editor: { name: 'Editor', permissions: ['project.*', 'report.*'] },
	viewer: { name: 'Viewer', permissions: ['project.read', 'report.read'] },
}

const roles = makeRoleSource(APP_ROLES)

const roleGrant = (roleKey: string, scope: Scope | null): GrantRow => ({
	id: `g-${roleKey}-${scope ? `${scope.type}:${scope.value}` : 'global'}`,
	principal_id: 'p1',
	app: APP,
	role_key: roleKey,
	permissions: null,
	scope_type: scope?.type ?? null,
	scope_value: scope?.value ?? null,
	granted_by: null,
	expires_at: null,
	created_at: 0,
})

const inlineGrant = (permissions: string[], scope: Scope | null): GrantRow => ({
	id: `gi-${permissions.join(',')}`,
	principal_id: 'p1',
	app: APP,
	role_key: null,
	permissions: JSON.stringify(permissions),
	scope_type: scope?.type ?? null,
	scope_value: scope?.value ?? null,
	granted_by: null,
	expires_at: null,
	created_at: 0,
})

const mapping = (roleKey: string, groupRef: string, scope: Scope | null): { mapping: GroupMappingRow; groupRef: string } => ({
	groupRef,
	mapping: {
		id: `m-${roleKey}`,
		provider: 'github',
		group_ref: groupRef,
		role_key: roleKey,
		app: APP,
		scope_type: scope?.type ?? null,
		scope_value: scope?.value ?? null,
		created_at: 0,
	},
})

const TEAM = (value: string): Scope => ({ type: 'team', value })

const scopeEq = (a: Scope | null, b: Scope | null): boolean => a === null ? b === null : b !== null && a.type === b.type && a.value === b.value

const has = (entries: PermissionEntry[], action: string, scope: Scope | null, source: string): boolean =>
	entries.some((e) => e.action === action && scopeEq(e.scope, scope) && e.source === source)

const base: ResolutionInputs = { app: APP, grants: [], groupMappings: [], isBootstrapAdmin: false }

describe('computePermissions — role grants', () => {
	test('expands a grant role into its permission patterns (source grant)', () => {
		const entries = computePermissions({ ...base, grants: [roleGrant('viewer', null)] }, roles)
		expect(has(entries, 'project.read', null, 'grant')).toBe(true)
		expect(has(entries, 'report.read', null, 'grant')).toBe(true)
		expect(entries).toHaveLength(2)
	})

	test('wildcard patterns stay as patterns (not pre-expanded)', () => {
		const entries = computePermissions({ ...base, grants: [roleGrant('editor', null)] }, roles)
		expect(has(entries, 'project.*', null, 'grant')).toBe(true)
		expect(has(entries, 'report.*', null, 'grant')).toBe(true)
		expect(entries).toHaveLength(2)
	})

	test('editor wildcard patterns are scoped to the grant scope', () => {
		const entries = computePermissions({ ...base, grants: [roleGrant('editor', TEAM('acme'))] }, roles)
		expect(has(entries, 'project.*', TEAM('acme'), 'grant')).toBe(true)
		expect(has(entries, 'report.*', TEAM('acme'), 'grant')).toBe(true)
	})

	test('dangling role key resolves to zero permissions (fail-closed)', () => {
		const entries = computePermissions({ ...base, grants: [roleGrant('ghost', null)] }, roles)
		expect(entries).toEqual([])
	})
})

describe('computePermissions — inline grants', () => {
	test('inline permissions are added directly as patterns with source grant', () => {
		const entries = computePermissions({ ...base, grants: [inlineGrant(['report.export', 'report.read'], TEAM('acme'))] }, roles)
		expect(has(entries, 'report.export', TEAM('acme'), 'grant')).toBe(true)
		expect(has(entries, 'report.read', TEAM('acme'), 'grant')).toBe(true)
		expect(entries).toHaveLength(2)
	})

	test('an inline wildcard pattern stays a pattern', () => {
		const entries = computePermissions({ ...base, grants: [inlineGrant(['report.*'], null)] }, roles)
		expect(entries).toEqual([{ action: 'report.*', scope: null, source: 'grant' }])
	})

	test('a role grant and an inline grant union (no role lookup for inline)', () => {
		const entries = computePermissions(
			{ ...base, grants: [roleGrant('viewer', null), inlineGrant(['report.export'], TEAM('acme'))] },
			roles,
		)
		expect(has(entries, 'project.read', null, 'grant')).toBe(true)
		expect(has(entries, 'report.export', TEAM('acme'), 'grant')).toBe(true)
	})
})

describe('computePermissions — built-in admin & per-app resolution', () => {
	test('the built-in admin role resolves even with no app DB roles loaded', () => {
		const emptyRoles = makeRoleSource({})
		const entries = computePermissions(
			{ app: APP, grants: [roleGrant('admin', null)], groupMappings: [], isBootstrapAdmin: false },
			emptyRoles,
		)
		expect(entries).toEqual([{ action: '*', scope: null, source: 'grant' }])
	})

	test('admin resolves at app=null (cross-app) too', () => {
		const emptyRoles = makeRoleSource({})
		const adminGrant: GrantRow = { ...roleGrant('admin', null), app: null }
		const entries = computePermissions(
			{ app: null, grants: [adminGrant], groupMappings: [], isBootstrapAdmin: false },
			emptyRoles,
		)
		expect(entries).toEqual([{ action: '*', scope: null, source: 'grant' }])
	})

	test('an app role unknown to the loaded source is dangling (fail-closed)', () => {
		// `viewer` lives in APP_ROLES; an empty source must not resolve it.
		const emptyRoles = makeRoleSource({})
		const entries = computePermissions(
			{ app: APP, grants: [roleGrant('viewer', null)], groupMappings: [], isBootstrapAdmin: false },
			emptyRoles,
		)
		expect(entries).toEqual([])
	})
})

describe('computePermissions — groups & bootstrap', () => {
	test('group-derived roles carry source group:<ref>', () => {
		const entries = computePermissions({ ...base, groupMappings: [mapping('editor', 'acme/core', TEAM('acme'))] }, roles)
		expect(has(entries, 'project.*', TEAM('acme'), 'group:acme/core')).toBe(true)
		expect(has(entries, 'report.*', TEAM('acme'), 'group:acme/core')).toBe(true)
	})

	test('bootstrap admin unions a global admin role with source bootstrap', () => {
		const entries = computePermissions({ ...base, isBootstrapAdmin: true }, roles)
		expect(entries).toEqual([{ action: '*', scope: null, source: 'bootstrap' }])
	})

	test('unions all sources', () => {
		const entries = computePermissions(
			{
				app: APP,
				grants: [roleGrant('viewer', TEAM('acme'))],
				groupMappings: [mapping('editor', 'acme/core', null)],
				isBootstrapAdmin: true,
			},
			roles,
		)
		expect(has(entries, 'project.read', TEAM('acme'), 'grant')).toBe(true)
		expect(has(entries, 'project.*', null, 'group:acme/core')).toBe(true)
		expect(has(entries, '*', null, 'bootstrap')).toBe(true)
	})
})

describe('computePermissions — dedup', () => {
	test('dedupes identical (action, scope, source)', () => {
		const entries = computePermissions({ ...base, grants: [roleGrant('viewer', null), roleGrant('viewer', null)] }, roles)
		expect(entries).toHaveLength(2)
	})

	test('same permission from different sources is kept separately (source distinguishes)', () => {
		const entries = computePermissions(
			{ ...base, grants: [roleGrant('viewer', null)], groupMappings: [mapping('viewer', 'acme/core', null)] },
			roles,
		)
		expect(has(entries, 'project.read', null, 'grant')).toBe(true)
		expect(has(entries, 'project.read', null, 'group:acme/core')).toBe(true)
	})

	test('no sources → empty', () => {
		expect(computePermissions(base, roles)).toEqual([])
	})
})
