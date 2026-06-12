import { describe, expect, test } from 'bun:test'
import { isActionAllowed, matchAction, permits, scopedValues } from '../permissions'
import type { PermissionEntry, Scope } from '../types'

describe('matchAction', () => {
	test('exact match', () => {
		expect(matchAction('project.read', 'project.read')).toBe(true)
	})

	test('exact non-match', () => {
		expect(matchAction('project.read', 'project.write')).toBe(false)
	})

	test("'*' matches everything", () => {
		expect(matchAction('*', 'x.y')).toBe(true)
		expect(matchAction('*', 'anything.at.all')).toBe(true)
		expect(matchAction('*', '')).toBe(true)
	})

	test("'prefix.*' matches a single nested segment", () => {
		expect(matchAction('project.*', 'project.read')).toBe(true)
	})

	test("'prefix.*' matches multiple nested segments", () => {
		expect(matchAction('project.*', 'project.settings.update')).toBe(true)
	})

	test("'prefix.*' does NOT match a different prefix sharing a string prefix", () => {
		// The dot boundary matters: 'projects' is not 'project'.
		expect(matchAction('project.*', 'projects.read')).toBe(false)
	})

	test("'prefix.*' does not match an unrelated namespace", () => {
		expect(matchAction('project.*', 'report.read')).toBe(false)
	})
})

const scope = (type: string, value: string): Scope => ({ type, value })

const entry = (action: string, s: Scope | null): PermissionEntry => ({
	action,
	scope: s,
	source: 'grant',
})

describe('permits', () => {
	test('scope-less check is satisfied only by a global entry', () => {
		expect(permits([entry('project.read', null)], 'project.read')).toBe(true)
	})

	test('scope-less check is NOT satisfied by a scoped entry', () => {
		expect(permits([entry('project.read', scope('project', 'p1'))], 'project.read')).toBe(false)
	})

	test('scoped check is satisfied by a global entry', () => {
		expect(permits([entry('project.read', null)], 'project.read', scope('project', 'p1'))).toBe(true)
	})

	test('scoped check is satisfied by a same-(type,value) entry', () => {
		expect(permits([entry('project.read', scope('project', 'p1'))], 'project.read', scope('project', 'p1'))).toBe(true)
	})

	test('scoped check is NOT satisfied by a different-value entry', () => {
		expect(permits([entry('project.read', scope('project', 'p2'))], 'project.read', scope('project', 'p1'))).toBe(false)
	})

	test('scoped check is NOT satisfied by a same-value entry in a different dimension', () => {
		// Dimensions are independent: ('team','p1') says nothing about ('project','p1').
		expect(permits([entry('project.read', scope('team', 'p1'))], 'project.read', scope('project', 'p1'))).toBe(false)
	})

	test('wildcard action entry grants a concrete action (scope-less)', () => {
		expect(permits([entry('project.*', null)], 'project.read')).toBe(true)
		expect(permits([entry('*', null)], 'anything.goes')).toBe(true)
	})

	test('wildcard action entry grants a concrete action (scoped)', () => {
		expect(
			permits([entry('project.*', scope('project', 'p1'))], 'project.settings.update', scope('project', 'p1')),
		).toBe(true)
	})

	test('no entries → false', () => {
		expect(permits([], 'project.read')).toBe(false)
		expect(permits([], 'project.read', scope('project', 'p1'))).toBe(false)
	})

	test('first matching entry wins across a mixed list', () => {
		const entries: PermissionEntry[] = [
			entry('report.read', scope('project', 'p2')),
			entry('project.*', scope('project', 'p1')),
			entry('other.thing', null),
		]
		expect(permits(entries, 'project.read', scope('project', 'p1'))).toBe(true)
		expect(permits(entries, 'project.read')).toBe(false)
	})
})

describe('scopedValues', () => {
	test('a matching global entry → null (unrestricted)', () => {
		expect(scopedValues([entry('project.read', null)], 'project.read', 'project')).toBeNull()
	})

	test('a matching global entry short-circuits over scoped entries → null', () => {
		const entries: PermissionEntry[] = [
			entry('project.read', scope('project', 'p1')),
			entry('project.read', null),
			entry('project.read', scope('project', 'p2')),
		]
		expect(scopedValues(entries, 'project.read', 'project')).toBeNull()
	})

	test('scoped entries → the distinct matching values', () => {
		const entries: PermissionEntry[] = [
			entry('project.read', scope('project', 'p1')),
			entry('project.read', scope('project', 'p2')),
		]
		expect(scopedValues(entries, 'project.read', 'project')).toEqual(['p1', 'p2'])
	})

	test('duplicate values are de-duplicated, order preserved', () => {
		const entries: PermissionEntry[] = [
			entry('project.read', scope('project', 'p2')),
			entry('project.*', scope('project', 'p2')),
			entry('project.read', scope('project', 'p1')),
		]
		expect(scopedValues(entries, 'project.read', 'project')).toEqual(['p2', 'p1'])
	})

	test('no matching entry → [] (no access)', () => {
		expect(scopedValues([entry('report.read', scope('project', 'p1'))], 'project.read', 'project')).toEqual([])
		expect(scopedValues([], 'project.read', 'project')).toEqual([])
	})

	test('entries in a different dimension are ignored → []', () => {
		const entries: PermissionEntry[] = [
			entry('project.read', scope('team', 'core')),
			entry('project.read', scope('organization', 'acme')),
		]
		expect(scopedValues(entries, 'project.read', 'project')).toEqual([])
	})

	test('only same-dimension values are collected', () => {
		const entries: PermissionEntry[] = [
			entry('project.read', scope('project', 'p1')),
			entry('project.read', scope('team', 'core')),
			entry('project.read', scope('project', 'p2')),
		]
		expect(scopedValues(entries, 'project.read', 'project')).toEqual(['p1', 'p2'])
	})

	test('wildcard action entry contributes its scope value', () => {
		expect(scopedValues([entry('project.*', scope('project', 'p1'))], 'project.read', 'project')).toEqual(['p1'])
	})
})

describe('isActionAllowed', () => {
	const catalog = ['project.read', 'project.settings.update', 'report.read']

	test("'*' is always allowed", () => {
		expect(isActionAllowed('*', catalog)).toBe(true)
		expect(isActionAllowed('*', [])).toBe(true)
	})

	test('exact action present in the catalog is allowed', () => {
		expect(isActionAllowed('project.read', catalog)).toBe(true)
		expect(isActionAllowed('project.settings.update', catalog)).toBe(true)
	})

	test('exact action absent from the catalog is rejected', () => {
		expect(isActionAllowed('project.delete', catalog)).toBe(false)
	})

	test("'prefix.*' is allowed when the catalog has an action under that namespace", () => {
		expect(isActionAllowed('project.*', catalog)).toBe(true)
		expect(isActionAllowed('report.*', catalog)).toBe(true)
	})

	test("'prefix.*' is rejected when the namespace is empty in the catalog", () => {
		expect(isActionAllowed('audit.*', catalog)).toBe(false)
	})

	test("'prefix.*' respects the dot boundary", () => {
		// 'project.*' must not be satisfied by an action like 'projectx.read'.
		expect(isActionAllowed('project.*', ['projectx.read'])).toBe(false)
	})

	test('unknown non-wildcard pattern is rejected', () => {
		expect(isActionAllowed('nope', catalog)).toBe(false)
	})
})
