import type { AppAccess } from '@propustka/core'
import { describe, expect, test } from 'bun:test'
import { managedName, parseManagedName, readAppAccess, reconcileAccess, ReconcileAccessError, ruleToSpec } from '../admin/reconcile-access'
import { FakeCfAccess } from './helpers/fake-cfaccess'

describe('ruleToSpec (rule → Cloudflare decision/include)', () => {
	test('service-auth → non_identity / any valid service token', () => {
		expect(ruleToSpec('opice', 'operator', { kind: 'service-auth' })).toEqual({
			name: 'px:opice:operator:service-auth',
			decision: 'non_identity',
			include: [{ any_valid_service_token: {} }],
		})
	})

	test('public → bypass / everyone', () => {
		expect(ruleToSpec('opice', 'public', { kind: 'public' })).toEqual({
			name: 'px:opice:public:public',
			decision: 'bypass',
			include: [{ everyone: {} }],
		})
	})

	test('human → allow, email_domain + email includes in order', () => {
		expect(ruleToSpec('poplach', 'operator', { kind: 'human', emailDomains: ['contember.com'], emails: ['a@x.cz'] })).toEqual({
			name: 'px:poplach:operator:human',
			decision: 'allow',
			include: [{ email_domain: { domain: 'contember.com' } }, { email: { email: 'a@x.cz' } }],
		})
	})

	test('a human rule with no domains/emails throws (defensive — never an open allow)', () => {
		expect(() => ruleToSpec('opice', 'operator', { kind: 'human' })).toThrow(ReconcileAccessError)
	})
})

describe('managed name round-trip', () => {
	test('parseManagedName recovers key (incl. hyphen) + kind, rejects foreign names', () => {
		expect(parseManagedName('example-app', managedName('example-app', 'main-host', 'service-auth'))).toEqual({
			key: 'main-host',
			kind: 'service-auth',
		})
		// A different app's policy name is not ours.
		expect(parseManagedName('opice', 'px:poplach:operator:human')).toBeNull()
		// A hand-made (non-managed) policy is not ours.
		expect(parseManagedName('opice', 'opice service auth')).toBeNull()
	})
})

// One gated app (service-auth before human) + a public carve-out — the common shape.
const DECL: AppAccess = {
	apps: [
		{
			key: 'operator',
			name: 'opice-operator',
			destinations: ['opice.example.com'],
			rules: [{ kind: 'service-auth' }, { kind: 'human', emailDomains: ['contember.com'] }],
		},
		{ key: 'public', name: 'opice-public', destinations: ['opice.example.com/s'], rules: [{ kind: 'public' }] },
	],
}

describe('reconcileAccess convergence', () => {
	test('creates apps + reusable policies and attaches them in precedence order', async () => {
		const cf = new FakeCfAccess()
		const readback = await reconcileAccess(cf, 'opice', DECL)

		// Two managed policies for the gated app, one for the bypass app.
		expect(readback.policies.map((p) => p.name).sort()).toEqual([
			'px:opice:operator:human',
			'px:opice:operator:service-auth',
			'px:opice:public:public',
		])

		// The gated app points at [service-auth, human] in that order (precedence = declared order).
		const operator = await cf.findAppByName('opice-operator')
		const svc = [...cf.policies.values()].find((p) => p.name === 'px:opice:operator:service-auth')
		const human = [...cf.policies.values()].find((p) => p.name === 'px:opice:operator:human')
		if (!svc || !human) {
			throw new Error('expected both managed policies to exist')
		}
		expect(operator?.policyIds).toEqual([svc.id, human.id])

		// Every app-policy write carried a non-empty array (never policy-less mid-flight).
		expect(cf.appPolicyWrites.length).toBeGreaterThan(0)
		for (const write of cf.appPolicyWrites) {
			expect(write.policyIds.length).toBeGreaterThan(0)
		}
	})

	test('is idempotent — re-run updates in place (stable ids, no duplicates)', async () => {
		const cf = new FakeCfAccess()
		await reconcileAccess(cf, 'opice', DECL)
		const idsAfterFirst = new Map([...cf.policies.values()].map((p) => [p.name, p.id]))

		await reconcileAccess(cf, 'opice', DECL)
		const idsAfterSecond = new Map([...cf.policies.values()].map((p) => [p.name, p.id]))

		expect(cf.policies.size).toBe(3) // no duplicates created
		expect(idsAfterSecond).toEqual(idsAfterFirst) // ids stable
	})

	test('atomic swap drops legacy inline policies off an existing app', async () => {
		const cf = new FakeCfAccess()
		// An app that already exists carrying a legacy inline policy.
		cf.seedApp({ id: 'app-legacy', name: 'opice-operator', destinations: ['opice.example.com'], policyIds: ['legacy-inline-1'] })

		await reconcileAccess(cf, 'opice', {
			apps: [{
				key: 'operator',
				name: 'opice-operator',
				destinations: ['opice.example.com'],
				rules: [{ kind: 'service-auth' }, { kind: 'human', emailDomains: ['contember.com'] }],
			}],
		})

		const app = await cf.findAppByName('opice-operator')
		expect(app?.policyIds).not.toContain('legacy-inline-1') // legacy dropped off
		expect(app?.policyIds).toHaveLength(2) // exactly the two managed reusable policies
	})

	test('orphan cleanup deletes only our no-longer-desired managed policies; spares hand-made + other apps', async () => {
		const cf = new FakeCfAccess()
		// A hand-made (non-managed) reusable policy that must survive untouched.
		await cf.createReusablePolicy({ name: 'opice service auth', decision: 'non_identity', include: [{ any_valid_service_token: {} }] })

		// First converge with service-auth + human on the gated app.
		await reconcileAccess(cf, 'opice', {
			apps: [{
				key: 'operator',
				name: 'opice-operator',
				destinations: ['opice.example.com'],
				rules: [{ kind: 'service-auth' }, { kind: 'human', emailDomains: ['contember.com'] }],
			}],
		})
		expect([...cf.policies.values()].some((p) => p.name === 'px:opice:operator:service-auth')).toBe(true)

		// Re-converge dropping the service-auth rule → it becomes an unreferenced managed orphan.
		await reconcileAccess(cf, 'opice', {
			apps: [{
				key: 'operator',
				name: 'opice-operator',
				destinations: ['opice.example.com'],
				rules: [{ kind: 'human', emailDomains: ['contember.com'] }],
			}],
		})

		const names = [...cf.policies.values()].map((p) => p.name)
		expect(names).not.toContain('px:opice:operator:service-auth') // managed orphan deleted
		expect(names).toContain('px:opice:operator:human') // still desired
		expect(names).toContain('opice service auth') // hand-made policy spared
	})

	test('refuses a CF app with no rules (would leave it policy-less)', async () => {
		const cf = new FakeCfAccess()
		const empty: AppAccess = { apps: [{ key: 'operator', name: 'opice-operator', destinations: ['opice.example.com'], rules: [] }] }
		await expect(reconcileAccess(cf, 'opice', empty)).rejects.toBeInstanceOf(ReconcileAccessError)
	})
})

describe('readAppAccess', () => {
	test("returns only this app's managed policies, parsed + sorted", async () => {
		const cf = new FakeCfAccess()
		await reconcileAccess(cf, 'opice', DECL)
		await reconcileAccess(cf, 'poplach', {
			apps: [{ key: 'operator', name: 'poplach', destinations: ['poplach.example.com'], rules: [{ kind: 'service-auth' }] }],
		})

		const opice = await readAppAccess(cf, 'opice')
		expect(opice.app).toBe('opice')
		expect(opice.policies.map((p) => `${p.key}:${p.kind}`)).toEqual([
			'operator:human',
			'operator:service-auth',
			'public:public',
		])
		// Steady state: each managed policy is referenced by exactly one app.
		for (const p of opice.policies) {
			expect(p.appCount).toBe(1)
		}
	})
})
