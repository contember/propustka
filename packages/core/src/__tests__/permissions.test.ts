import { describe, expect, test } from 'bun:test'
import { matchAction, permits } from '../permissions'
import type { PermissionEntry } from '../types'

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

const entry = (action: string, projectId: string | null): PermissionEntry => ({
	action,
	projectId,
	source: 'grant',
})

describe('permits', () => {
	test('scope-less check is satisfied only by a global entry', () => {
		expect(permits([entry('project.read', null)], 'project.read')).toBe(true)
	})

	test('scope-less check is NOT satisfied by a project-scoped entry', () => {
		expect(permits([entry('project.read', 'p1')], 'project.read')).toBe(false)
	})

	test('project scope is satisfied by a global entry', () => {
		expect(permits([entry('project.read', null)], 'project.read', 'p1')).toBe(true)
	})

	test('project scope is satisfied by a same-project entry', () => {
		expect(permits([entry('project.read', 'p1')], 'project.read', 'p1')).toBe(true)
	})

	test('project scope is NOT satisfied by a different-project entry', () => {
		expect(permits([entry('project.read', 'p2')], 'project.read', 'p1')).toBe(false)
	})

	test('wildcard action entry grants a concrete action (scope-less)', () => {
		expect(permits([entry('project.*', null)], 'project.read')).toBe(true)
		expect(permits([entry('*', null)], 'anything.goes')).toBe(true)
	})

	test('wildcard action entry grants a concrete action (project scope)', () => {
		expect(permits([entry('project.*', 'p1')], 'project.settings.update', 'p1')).toBe(true)
	})

	test('no entries → false', () => {
		expect(permits([], 'project.read')).toBe(false)
		expect(permits([], 'project.read', 'p1')).toBe(false)
	})

	test('first matching entry wins across a mixed list', () => {
		const entries: PermissionEntry[] = [
			entry('report.read', 'p2'),
			entry('project.*', 'p1'),
			entry('other.thing', null),
		]
		expect(permits(entries, 'project.read', 'p1')).toBe(true)
		expect(permits(entries, 'project.read')).toBe(false)
	})
})
