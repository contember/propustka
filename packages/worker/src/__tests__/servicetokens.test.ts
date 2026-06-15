import type { PermissionEntry } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { findUncoveredAction } from '../servicetokens'

const global = (action: string): PermissionEntry => ({ action, scope: null, source: 'grant' })
const scoped = (action: string, type: string, value: string): PermissionEntry => ({ action, scope: { type, value }, source: 'grant' })

describe('findUncoveredAction (service-token delegation check)', () => {
	test('a global wildcard issuer covers any granted action on any scope', () => {
		expect(findUncoveredAction([global('*')], ['report.write', 'report.read'], { type: 'project', value: 'p' })).toBeNull()
	})

	test('a same-scope issuer grant covers the request', () => {
		expect(findUncoveredAction([scoped('report.write', 'project', 'p')], ['report.write'], { type: 'project', value: 'p' })).toBeNull()
	})

	test('a scoped issuer does NOT cover a different scope value', () => {
		expect(findUncoveredAction([scoped('report.write', 'project', 'p')], ['report.write'], { type: 'project', value: 'q' })).toBe('report.write')
	})

	test('returns the FIRST uncovered action', () => {
		expect(findUncoveredAction([global('report.read')], ['report.read', 'report.write'], { type: 'project', value: 'p' })).toBe('report.write')
	})

	test('a null scope (global grant) requires the issuer to hold the action globally', () => {
		expect(findUncoveredAction([scoped('report.write', 'project', 'p')], ['report.write'], null)).toBe('report.write')
		expect(findUncoveredAction([global('report.write')], ['report.write'], null)).toBeNull()
	})

	test('a namespace wildcard issuer (report.*) covers report.write on its scope', () => {
		expect(findUncoveredAction([scoped('report.*', 'project', 'p')], ['report.write'], { type: 'project', value: 'p' })).toBeNull()
	})
})
