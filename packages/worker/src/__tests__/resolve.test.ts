import type { PermissionEntry } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import type { GrantRow, GroupMappingRow } from '../db'
import { computePermissions } from '../resolve'

const grant = (roleKey: string, projectId: string | null): GrantRow => ({
	id: `g-${roleKey}-${projectId ?? 'global'}`,
	principal_id: 'p1',
	role_key: roleKey,
	project_id: projectId,
	app: null,
	granted_by: null,
	expires_at: null,
	created_at: 0,
})

const mapping = (roleKey: string, groupRef: string, projectId: string | null): { mapping: GroupMappingRow; groupRef: string } => ({
	groupRef,
	mapping: {
		id: `m-${roleKey}`,
		provider: 'github',
		group_ref: groupRef,
		role_key: roleKey,
		project_id: projectId,
		app: null,
		created_at: 0,
	},
})

const has = (entries: PermissionEntry[], action: string, projectId: string | null, source: string): boolean =>
	entries.some((e) => e.action === action && e.projectId === projectId && e.source === source)

describe('computePermissions', () => {
	test('expands a grant role into its permission patterns (source grant)', () => {
		const entries = computePermissions({ grants: [grant('viewer', null)], groupMappings: [], isBootstrapAdmin: false })
		expect(has(entries, 'project.read', null, 'grant')).toBe(true)
		expect(has(entries, 'report.read', null, 'grant')).toBe(true)
		expect(entries).toHaveLength(2)
	})

	test('wildcard patterns stay as patterns (not pre-expanded)', () => {
		const entries = computePermissions({ grants: [grant('admin', null)], groupMappings: [], isBootstrapAdmin: false })
		expect(entries).toEqual([{ action: '*', projectId: null, source: 'grant' }])
	})

	test('editor wildcard patterns are preserved', () => {
		const entries = computePermissions({ grants: [grant('editor', 'p1')], groupMappings: [], isBootstrapAdmin: false })
		expect(has(entries, 'project.*', 'p1', 'grant')).toBe(true)
		expect(has(entries, 'report.*', 'p1', 'grant')).toBe(true)
	})

	test('group-derived roles carry source group:<ref>', () => {
		const entries = computePermissions({
			grants: [],
			groupMappings: [mapping('editor', 'acme/core', 'p1')],
			isBootstrapAdmin: false,
		})
		expect(has(entries, 'project.*', 'p1', 'group:acme/core')).toBe(true)
		expect(has(entries, 'report.*', 'p1', 'group:acme/core')).toBe(true)
	})

	test('bootstrap admin unions a global admin role with source bootstrap', () => {
		const entries = computePermissions({ grants: [], groupMappings: [], isBootstrapAdmin: true })
		expect(entries).toEqual([{ action: '*', projectId: null, source: 'bootstrap' }])
	})

	test('unions all three sources', () => {
		const entries = computePermissions({
			grants: [grant('viewer', 'p1')],
			groupMappings: [mapping('editor', 'acme/core', null)],
			isBootstrapAdmin: true,
		})
		expect(has(entries, 'project.read', 'p1', 'grant')).toBe(true)
		expect(has(entries, 'project.*', null, 'group:acme/core')).toBe(true)
		expect(has(entries, '*', null, 'bootstrap')).toBe(true)
	})

	test('dedupes identical (action, projectId, source)', () => {
		// Two grants of the same role + scope must not duplicate entries.
		const entries = computePermissions({
			grants: [grant('viewer', null), grant('viewer', null)],
			groupMappings: [],
			isBootstrapAdmin: false,
		})
		expect(entries).toHaveLength(2)
	})

	test('same permission from different sources is kept separately (source distinguishes)', () => {
		const entries = computePermissions({
			grants: [grant('viewer', null)],
			groupMappings: [mapping('viewer', 'acme/core', null)],
			isBootstrapAdmin: false,
		})
		expect(has(entries, 'project.read', null, 'grant')).toBe(true)
		expect(has(entries, 'project.read', null, 'group:acme/core')).toBe(true)
	})

	test('dangling role key resolves to zero permissions (fail-closed)', () => {
		const entries = computePermissions({ grants: [grant('ghost', null)], groupMappings: [], isBootstrapAdmin: false })
		expect(entries).toEqual([])
	})

	test('no sources → empty', () => {
		expect(computePermissions({ grants: [], groupMappings: [], isBootstrapAdmin: false })).toEqual([])
	})
})
