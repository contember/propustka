import { describe, expect, test } from 'bun:test'
import { uuidv7 } from '../ids'

const UUID_V7_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/

describe('uuidv7', () => {
	test('returns a valid v7 UUID in canonical lowercase form', () => {
		for (let i = 0; i < 100; i++) {
			expect(uuidv7()).toMatch(UUID_V7_RE)
		}
	})

	test('is unique across many calls', () => {
		const count = 10_000
		const ids = new Set<string>()
		for (let i = 0; i < count; i++) {
			ids.add(uuidv7())
		}
		expect(ids.size).toBe(count)
	})

	test('is time-sortable: an id generated later sorts >= one generated earlier', () => {
		const earlier = uuidv7()

		// Busy-wait until the wall clock advances at least 2ms so the timestamp prefix differs.
		const start = Date.now()
		while (Date.now() - start < 2) {
			// spin
		}

		const later = uuidv7()

		expect(later >= earlier).toBe(true)
		expect(later > earlier).toBe(true)
	})

	test('lexicographic order tracks generation time across a small gap', () => {
		const ids: string[] = []
		for (let batch = 0; batch < 5; batch++) {
			ids.push(uuidv7())
			const start = Date.now()
			while (Date.now() - start < 2) {
				// spin to advance the ms timestamp between batches
			}
		}

		const sorted = [...ids].sort()
		expect(sorted).toEqual(ids)
	})
})
