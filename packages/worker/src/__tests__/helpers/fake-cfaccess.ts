import type { CfAccess, CfApp, CfAppSpec, CfPolicy, CfPolicySpec } from '../../cfaccess'

/**
 * In-memory `CfAccess` for tests — no network. Mirrors the bits Access-rules reconcile uses:
 * an account-level reusable-policy store and an app store whose `policyIds` are repointed by
 * `updateAppPolicies`. Records every app-policy write so tests can assert the attach-before-detach
 * ordering (and that an empty array is never PUT).
 */

interface StoredPolicy {
	id: string
	name: string
	decision: string
	include: unknown[]
}

export class FakeCfAccess implements CfAccess {
	private seq = 0
	readonly policies = new Map<string, StoredPolicy>()
	readonly apps = new Map<string, CfApp>()
	/** Every `updateAppPolicies` call, in order — for ordering/never-empty assertions. */
	readonly appPolicyWrites: { appId: string; policyIds: string[] }[] = []

	private nextId(prefix: string): string {
		this.seq += 1
		return `${prefix}-${this.seq}`
	}

	private appCount(policyId: string): number {
		let count = 0
		for (const app of this.apps.values()) {
			if (app.policyIds.includes(policyId)) {
				count += 1
			}
		}
		return count
	}

	// ── reusable policies ───────────────────────────────────────────────────────

	listReusablePolicies(): Promise<CfPolicy[]> {
		const out: CfPolicy[] = []
		for (const p of this.policies.values()) {
			out.push({ id: p.id, name: p.name, decision: p.decision, appCount: this.appCount(p.id) })
		}
		return Promise.resolve(out)
	}

	createReusablePolicy(spec: CfPolicySpec): Promise<CfPolicy> {
		const id = this.nextId('pol')
		this.policies.set(id, { id, name: spec.name, decision: spec.decision, include: spec.include })
		return Promise.resolve({ id, name: spec.name, decision: spec.decision, appCount: 0 })
	}

	updateReusablePolicy(id: string, spec: CfPolicySpec): Promise<CfPolicy> {
		this.policies.set(id, { id, name: spec.name, decision: spec.decision, include: spec.include })
		return Promise.resolve({ id, name: spec.name, decision: spec.decision, appCount: this.appCount(id) })
	}

	deleteReusablePolicy(id: string): Promise<void> {
		this.policies.delete(id)
		return Promise.resolve()
	}

	// ── apps ────────────────────────────────────────────────────────────────────

	findAppByName(name: string): Promise<CfApp | null> {
		for (const app of this.apps.values()) {
			if (app.name === name) {
				return Promise.resolve(app)
			}
		}
		return Promise.resolve(null)
	}

	createApp(spec: CfAppSpec): Promise<CfApp> {
		const id = this.nextId('app')
		const app: CfApp = {
			id,
			name: spec.name,
			aud: `${id}.aud`,
			type: 'self_hosted',
			domain: spec.destinations[0] ?? null,
			sessionDuration: spec.sessionDuration ?? '24h',
			destinations: spec.destinations.map((uri) => ({ type: 'public', uri })),
			policyIds: [],
		}
		this.apps.set(id, app)
		return Promise.resolve(app)
	}

	getApp(id: string): Promise<CfApp> {
		const app = this.apps.get(id)
		if (!app) {
			return Promise.reject(new Error(`fake: app ${id} not found`))
		}
		return Promise.resolve(app)
	}

	updateAppPolicies(app: CfApp, policyIds: string[]): Promise<void> {
		const stored = this.apps.get(app.id)
		if (stored) {
			this.apps.set(app.id, { ...stored, policyIds: [...policyIds] })
		}
		this.appPolicyWrites.push({ appId: app.id, policyIds: [...policyIds] })
		return Promise.resolve()
	}

	// ── test seeding ────────────────────────────────────────────────────────────

	/** Seed a pre-existing app (e.g. one carrying legacy inline policies) into the store. */
	seedApp(app: { id: string; name: string; destinations?: string[]; policyIds?: string[] }): CfApp {
		const destinations = (app.destinations ?? [app.name]).map((uri) => ({ type: 'public', uri }))
		const full: CfApp = {
			id: app.id,
			name: app.name,
			aud: `${app.id}.aud`,
			type: 'self_hosted',
			domain: destinations[0]?.uri ?? app.name,
			sessionDuration: '24h',
			destinations,
			policyIds: app.policyIds ?? [],
		}
		this.apps.set(full.id, full)
		return full
	}
}
