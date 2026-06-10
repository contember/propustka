import { describe, expect, test } from 'bun:test'
import { normalizeGroupRef, parseGroupRefs } from '../identity'

describe('normalizeGroupRef', () => {
	test('lowercases org and team', () => {
		expect(normalizeGroupRef('My-Org', 'Core-Devs')).toBe('my-org/core-devs')
	})

	test('trims surrounding whitespace', () => {
		expect(normalizeGroupRef(' Acme ', ' Platform ')).toBe('acme/platform')
	})

	test('joins with a single slash', () => {
		expect(normalizeGroupRef('a', 'b')).toBe('a/b')
	})
})

describe('parseGroupRefs', () => {
	test('parses org/team strings', () => {
		expect(parseGroupRefs({ groups: ['My-Org/Core-Devs', 'acme/platform'] }))
			.toEqual(['my-org/core-devs', 'acme/platform'])
	})

	test('parses { name } objects', () => {
		expect(parseGroupRefs({ groups: [{ name: 'My-Org/Core-Devs' }] }))
			.toEqual(['my-org/core-devs'])
	})

	test('dedupes equivalent refs', () => {
		expect(parseGroupRefs({ groups: ['My-Org/Team', 'my-org/team'] }))
			.toEqual(['my-org/team'])
	})

	test('ignores flat groups without a team part', () => {
		expect(parseGroupRefs({ groups: ['just-an-org', '/leading', 'trailing/'] }))
			.toEqual([])
	})

	test('returns [] for a non-object body', () => {
		expect(parseGroupRefs(null)).toEqual([])
		expect(parseGroupRefs('nope')).toEqual([])
		expect(parseGroupRefs(42)).toEqual([])
	})

	test('returns [] when groups is missing or not an array', () => {
		expect(parseGroupRefs({})).toEqual([])
		expect(parseGroupRefs({ groups: 'x' })).toEqual([])
	})

	test('skips malformed group entries', () => {
		expect(parseGroupRefs({ groups: [123, null, { id: 1 }, 'org/team'] }))
			.toEqual(['org/team'])
	})
})
