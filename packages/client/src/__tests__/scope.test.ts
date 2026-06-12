import { describe, expect, test } from 'bun:test'
import { applyScope } from '../scope'

describe('applyScope', () => {
	const branches = {
		all: () => 'ALL' as const,
		some: (values: string[]) => `SOME:${values.join(',')}` as const,
		none: () => 'NONE' as const,
	}

	test('null → all()', () => {
		expect(applyScope(null, branches)).toBe('ALL')
	})

	test('[] → none() (never emits WHERE col IN ())', () => {
		expect(applyScope([], branches)).toBe('NONE')
	})

	test('non-empty → some(values) (opaque, app-owned scope values)', () => {
		expect(applyScope(['acme', 'globex'], branches)).toBe('SOME:acme,globex')
	})
})
