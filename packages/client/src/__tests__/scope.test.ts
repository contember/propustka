import { describe, expect, test } from 'bun:test'
import { applyScope } from '../scope'

describe('applyScope', () => {
	const branches = {
		all: () => 'ALL' as const,
		some: (ids: string[]) => `SOME:${ids.join(',')}` as const,
		none: () => 'NONE' as const,
	}

	test('null → all()', () => {
		expect(applyScope(null, branches)).toBe('ALL')
	})

	test('[] → none() (never emits WHERE id IN ())', () => {
		expect(applyScope([], branches)).toBe('NONE')
	})

	test('non-empty → some(ids)', () => {
		expect(applyScope(['p1', 'p2'], branches)).toBe('SOME:p1,p2')
	})
})
