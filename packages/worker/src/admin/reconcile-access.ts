/**
 * Reconcile an app's declared Access edge rules into Cloudflare — Access-as-code, EDGE edition
 * (the front-door counterpart of the schema reconcile in handlers.ts). An app declares an
 * `AppAccess` (one or more CF Access applications, each with `service-auth` / `human` / `public`
 * rules); this converges Cloudflare's account-level REUSABLE policies + the apps' `policies`
 * arrays to match.
 *
 * Ownership guard (the CF analogue of the schema reconcile's origin='app' vs 'custom' rule):
 * reconcile creates/updates/deletes ONLY policies whose name carries the managed prefix
 * `px:<appId>:` — admin/operator-made policies (any other name) are never touched.
 *
 * Idempotent + lock-out-safe: policies are matched by managed name (update in place, ids stable);
 * an app's policies are swapped in ONE full-replace PUT (never an empty array, so the app is never
 * policy-less mid-flight); orphaned managed policies are deleted only when no app still references
 * them (`app_count === 0`).
 */

import type { AccessAppDecl, AccessRule, AppAccess } from '@propustka/core'
import type { CfAccess, CfInclude, CfPolicySpec } from '../cfaccess'

/** The three rule kinds (mirrors `AccessRule['kind']`). */
export type AccessRuleKind = AccessRule['kind']

const RULE_KINDS: readonly AccessRuleKind[] = ['service-auth', 'human', 'public']

/** Managed-policy name prefix for one app id — the ownership boundary reconcile respects. */
export function managedPrefix(appId: string): string {
	return `px:${appId}:`
}

/** The managed name of the reusable policy for `(appId, cfAppKey, ruleKind)`. */
export function managedName(appId: string, cfAppKey: string, kind: AccessRuleKind): string {
	return `${managedPrefix(appId)}${cfAppKey}:${kind}`
}

/** Parse a managed policy name back into its `(key, kind)` for this app; null when not ours. */
export function parseManagedName(appId: string, name: string): { key: string; kind: string } | null {
	const prefix = managedPrefix(appId)
	if (!name.startsWith(prefix)) {
		return null
	}
	const rest = name.slice(prefix.length)
	const lastColon = rest.lastIndexOf(':')
	if (lastColon <= 0 || lastColon === rest.length - 1) {
		return null
	}
	return { key: rest.slice(0, lastColon), kind: rest.slice(lastColon + 1) }
}

/** Map one declared rule to its Cloudflare decision + include selectors. */
export function ruleToSpec(appId: string, cfAppKey: string, rule: AccessRule): CfPolicySpec {
	const name = managedName(appId, cfAppKey, rule.kind)
	switch (rule.kind) {
		case 'service-auth':
			return { name, decision: 'non_identity', include: [{ any_valid_service_token: {} }] }
		case 'public':
			return { name, decision: 'bypass', include: [{ everyone: {} }] }
		case 'human': {
			const include: CfInclude[] = [
				...(rule.emailDomains ?? []).map((domain) => ({ email_domain: { domain } })),
				...(rule.emails ?? []).map((email) => ({ email: { email } })),
			]
			if (include.length === 0) {
				// Guarded upstream by parseAppAccess; defensive so a bug can't create an open allow.
				throw new ReconcileAccessError(`human rule for '${cfAppKey}' has no emailDomains/emails`)
			}
			return { name, decision: 'allow', include }
		}
	}
}

/** Thrown when reconcile can't proceed safely (the handler maps it to a 502/400). */
export class ReconcileAccessError extends Error {
	constructor(message: string) {
		super(message)
		this.name = 'ReconcileAccessError'
	}
}

// ── Readback (shared by GET + the PUT response — always live CF state) ──────────

/** One managed reusable policy as read back for an app. */
export interface AccessPolicyReadback {
	/** The cfApp key parsed from the managed name. */
	key: string
	/** The rule kind parsed from the managed name (one of AccessRuleKind, or raw if unexpected). */
	kind: string
	name: string
	decision: string
	id: string
	/** How many CF apps reference this policy (1 in the steady state; 0 = orphan). */
	appCount: number
}

export interface AppAccessReadback {
	app: string
	policies: AccessPolicyReadback[]
}

/** Read the reusable policies propustka manages for `appId` (prefix-filtered, parsed, sorted). */
export async function readAppAccess(cf: CfAccess, appId: string): Promise<AppAccessReadback> {
	const all = await cf.listReusablePolicies()
	const policies: AccessPolicyReadback[] = []
	for (const p of all) {
		const parsed = parseManagedName(appId, p.name)
		if (parsed === null) {
			continue
		}
		policies.push({ key: parsed.key, kind: parsed.kind, name: p.name, decision: p.decision, id: p.id, appCount: p.appCount })
	}
	policies.sort((a, b) => (a.key === b.key ? a.kind.localeCompare(b.kind) : a.key.localeCompare(b.key)))
	return { app: appId, policies }
}

// ── Reconcile ───────────────────────────────────────────────────────────────────

/**
 * Converge Cloudflare to `decl` for `appId`. Returns the live readback. Throws
 * `ReconcileAccessError` / `CfAccessError` on a CF failure — the caller (putAppAccess) maps it to a
 * 502; because each CF app's swap is individually atomic + idempotent, a re-run finishes the rest.
 */
export async function reconcileAccess(cf: CfAccess, appId: string, decl: AppAccess): Promise<AppAccessReadback> {
	// Snapshot reusable policies once; index by name so a re-run updates in place (ids stable).
	const before = await cf.listReusablePolicies()
	const byName = new Map(before.map((p) => [p.name, p]))
	const desiredNames = new Set<string>()

	for (const appDecl of decl.apps) {
		if (appDecl.rules.length === 0) {
			throw new ReconcileAccessError(`CF app '${appDecl.name}' has no rules — would leave it policy-less`)
		}

		// 1. Resolve or create the CF Access application (by name).
		const cfApp = (await cf.findAppByName(appDecl.name))
			?? (await cf.createApp({
				name: appDecl.name,
				destinations: appDecl.destinations,
				...(appDecl.sessionDuration !== undefined ? { sessionDuration: appDecl.sessionDuration } : {}),
			}))

		// 2. Create/update each rule's reusable policy; collect ids in declared (precedence) order.
		const desiredIds: string[] = []
		for (const rule of appDecl.rules) {
			const spec = ruleToSpec(appId, appDecl.key, rule)
			desiredNames.add(spec.name)
			const existing = byName.get(spec.name)
			const policy = existing ? await cf.updateReusablePolicy(existing.id, spec) : await cf.createReusablePolicy(spec)
			byName.set(spec.name, policy)
			desiredIds.push(policy.id)
		}

		// 3. Atomic swap: repoint the app at the new reusable policies (legacy inline policies drop
		//    off here). desiredIds is guaranteed non-empty by the rules.length check above.
		const fresh = await cf.getApp(cfApp.id)
		await cf.updateAppPolicies(fresh, desiredIds)
	}

	// 4. Orphan cleanup — delete our managed policies no longer desired AND no longer referenced by
	//    any app (app_count === 0). Re-list for fresh counts post-swap; never touch non-`px:<appId>` names.
	const prefix = managedPrefix(appId)
	const after = await cf.listReusablePolicies()
	for (const p of after) {
		if (p.name.startsWith(prefix) && !desiredNames.has(p.name) && p.appCount === 0) {
			await cf.deleteReusablePolicy(p.id)
		}
	}

	return readAppAccess(cf, appId)
}

export { RULE_KINDS }
