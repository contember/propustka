#!/usr/bin/env bun
/**
 * Bootstrap propustka-admin's OWN Cloudflare Access front door — operator tool, DIRECT to the
 * Cloudflare API (the operator holds the token; nothing here is committed or logged). This is the
 * one irreducible chicken-and-egg step on a fresh account: the admin endpoint that every downstream
 * app's reconcile goes through can't gate itself until `propustka-admin` exists, so we create it
 * out-of-band from propustka's OWN committed declaration (`packages/worker/propustka.access.ts`).
 *
 * Downstream apps are NOT created here. Each app declares its own `propustka.access.ts` (+ schema)
 * and self-reconciles through the admin endpoint at deploy time, authenticated with a
 * propustka-issued provisioning key (see `scripts/provision-key.ts`). That replaces the old
 * hardcoded whole-stack list (poplach / opice) this script used to carry.
 *
 * It reuses the Worker's own `reconcileAccess` + `CfAccessClient` (no duplicated convergence logic),
 * driven with the OPERATOR token. Idempotent + lock-out-safe: managed policies (`px:<app>:…`) are
 * matched by name and updated in place, non-managed policies are never touched, and an EXISTING app
 * keeps its destinations (only its `policies` array changes) — so re-running never re-routes.
 *
 *   CF_API_TOKEN=…                            # Zero Trust → Access: Apps and Policies — Edit
 *   CF_ACCOUNT_ID=…
 *   PROPUSTKA_HOSTNAME=propustka.example.com   # propustka-admin's hostname (the Custom Domain)
 *   PROPUSTKA_ADMIN_EMAIL_DOMAINS=a.com,b.com  # optional; human rule; defaults to contember.com
 *   bun run scripts/provision-access.ts [--dry-run]
 *
 * --dry-run parses the committed declaration and prints the intended bootstrap without touching CF.
 */

import { propustkaAccess, propustkaAppId } from '../packages/worker/propustka.access'
import { reconcileAccess } from '../packages/worker/src/admin/reconcile-access'
import { CfAccessClient } from '../packages/worker/src/cfaccess'

function required(name: string): string {
	const value = process.env[name]
	if (value === undefined || value === '') {
		throw new Error(`Missing required env var ${name}`)
	}
	return value
}

const DRY_RUN = process.argv.includes('--dry-run')

function describe(): string[] {
	const lines = [`  • ${propustkaAppId}`]
	for (const cfApp of propustkaAccess.apps) {
		lines.push(`      ${cfApp.name}  [${cfApp.destinations.join(', ')}]`)
		lines.push(`          rules: ${cfApp.rules.map((r) => r.kind).join(', ')}`)
	}
	return lines
}

async function main(): Promise<void> {
	if (DRY_RUN) {
		console.log("DRY RUN — no changes. Would bootstrap propustka-admin's front door:\n")
		for (const line of describe()) console.log(line)
		console.log('\n1 app — none pushed (--dry-run).')
		return
	}

	// Fail loud if the target hostname wasn't set — otherwise the committed fallback would create a
	// `propustka.contember.com` app in whatever account CF_ACCOUNT_ID points at.
	required('PROPUSTKA_HOSTNAME')

	const cf = new CfAccessClient(required('CF_API_TOKEN'), required('CF_ACCOUNT_ID'))

	const readback = await reconcileAccess(cf, propustkaAppId, propustkaAccess)
	const policies = readback.policies.map((p) => `${p.key}:${p.kind}`).join(', ')
	console.log(`✓ ${propustkaAppId.padEnd(12)} ${readback.policies.length} reusable policy(ies): ${policies}`)

	// Collect aud → appId for the gated CF app so the PROPUSTKA_ACCESS_APPS Worker var can be pasted.
	const accessApps: Record<string, string> = {}
	for (const cfApp of propustkaAccess.apps) {
		if (cfApp.rules.every((r) => r.kind === 'public')) {
			continue
		}
		const app = await cf.findAppByName(cfApp.name)
		if (app) {
			accessApps[app.aud] = propustkaAppId
		}
	}

	console.log('\n— PROPUSTKA_ACCESS_APPS (paste into the propustka GitHub Environment variable) —')
	console.log(JSON.stringify(accessApps))
	console.log('\nDone. propustka-admin front door bootstrapped. Downstream apps self-reconcile with a provisioning key.')
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
