#!/usr/bin/env bun
/**
 * Provision the WHOLE stack's Cloudflare Access edge — operator tool, direct to the Cloudflare API
 * (the operator holds the token; nothing here is committed or logged). This is the BOOTSTRAP +
 * MIGRATION path: it reconciles every app's Access rules (service-auth / human / public) into
 * account-level REUSABLE policies, including `propustka-admin`'s own front door — which must exist
 * before the admin-endpoint (SDK) path `scripts/provision-access-rules.ts` is even reachable.
 *
 * It reuses the Worker's own `reconcileAccess` + `CfAccessClient` (no duplicated convergence logic),
 * just driven with the OPERATOR token instead of the Worker's. Idempotent + lock-out-safe: each
 * app's policies are swapped atomically, managed policies (`px:<app>:…`) are matched by name and
 * updated in place, and non-managed policies are never touched. EXISTING apps keep their
 * destinations (reconcile changes only the `policies` array) — so re-running never re-routes.
 *
 *   CF_API_TOKEN=…                    # Zero Trust → Access: Apps and Policies — Edit
 *   CF_ACCOUNT_ID=…
 *   ACCESS_DOMAIN=example.com         # hostnames become propustka. / poplach. / opice.<domain>
 *   # Humans (the `allow` rule). Default: email_domain <ACCESS_DOMAIN>. Override either:
 *   ACCESS_HUMAN_EMAIL_DOMAINS=a.com,b.com   # optional; defaults to [ACCESS_DOMAIN]
 *   ACCESS_HUMAN_EMAILS=a@x.cz,b@x.cz        # optional; explicit emails (in addition / instead)
 *   bun run scripts/provision-access.ts [--dry-run]
 */

import type { AccessRule, AppAccess } from '@propustka/core'
import { reconcileAccess } from '../packages/worker/src/admin/reconcile-access'
import { CfAccessClient } from '../packages/worker/src/cfaccess'

// ── env ──────────────────────────────────────────────────────────────────────

function required(name: string): string {
	const value = process.env[name]
	if (value === undefined || value === '') {
		throw new Error(`Missing required env var ${name}`)
	}
	return value
}

function list(name: string): string[] {
	const raw = process.env[name]
	if (raw === undefined || raw.trim() === '') {
		return []
	}
	return raw.split(',').map((s) => s.trim()).filter((s) => s.length > 0)
}

const DRY_RUN = process.argv.includes('--dry-run')

// ── stack declaration ──────────────────────────────────────────────────────────
//
// The operator's view of the whole stack's Access topology. Each app's own repo can ALSO declare
// this (a `propustka.access.ts`) and self-reconcile via the SDK once propustka-admin is up; this
// is the authoritative bootstrap/migration source.

function humanRule(): AccessRule {
	const domains = list('ACCESS_HUMAN_EMAIL_DOMAINS')
	const emails = list('ACCESS_HUMAN_EMAILS')
	const emailDomains = domains.length > 0 || emails.length > 0 ? domains : [required('ACCESS_DOMAIN')]
	if (emailDomains.length === 0 && emails.length === 0) {
		throw new Error('human rule needs ACCESS_HUMAN_EMAIL_DOMAINS, ACCESS_HUMAN_EMAILS, or ACCESS_DOMAIN')
	}
	return {
		kind: 'human',
		...(emailDomains.length > 0 ? { emailDomains } : {}),
		...(emails.length > 0 ? { emails } : {}),
	}
}

function buildDeclarations(domain: string): { app: string; access: AppAccess }[] {
	const human = humanRule()
	const serviceAuth: AccessRule = { kind: 'service-auth' }
	const publicRule: AccessRule = { kind: 'public' }
	const gated = [serviceAuth, human]
	return [
		{
			app: 'propustka',
			access: {
				apps: [
					{ key: 'admin', name: 'propustka-admin', destinations: [`propustka.${domain}`], rules: gated },
				],
			},
		},
		{
			app: 'poplach',
			access: {
				apps: [
					{ key: 'operator', name: 'poplach', destinations: [`poplach.${domain}`], rules: gated },
					{
						key: 'ingest',
						name: 'poplach-ingest',
						destinations: [`poplach.${domain}/api/*/envelope`, `poplach.${domain}/api/sourcemaps`],
						rules: [publicRule],
					},
				],
			},
		},
		{
			app: 'opice',
			access: {
				apps: [
					{ key: 'operator', name: 'opice-operator', destinations: [`opice.${domain}`], rules: gated },
					{
						key: 'public',
						name: 'opice-public',
						destinations: [`opice.${domain}/api/v1`, `opice.${domain}/s`, `opice.${domain}/install.md`],
						rules: [publicRule],
					},
				],
			},
		},
	]
}

// ── reporting ─────────────────────────────────────────────────────────────────

function describe(decl: { app: string; access: AppAccess }): string[] {
	const lines = [`  • ${decl.app}`]
	for (const cfApp of decl.access.apps) {
		lines.push(`      ${cfApp.name}  [${cfApp.destinations.join(', ')}]`)
		lines.push(`          rules: ${cfApp.rules.map((r) => r.kind).join(', ')}`)
	}
	return lines
}

// ── main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
	const domain = required('ACCESS_DOMAIN')
	const declarations = buildDeclarations(domain)

	if (DRY_RUN) {
		console.log('DRY RUN — no changes. Would reconcile these Access rules into reusable policies:\n')
		for (const decl of declarations) {
			for (const line of describe(decl)) console.log(line)
		}
		console.log(`\n${declarations.length} app(s) — none pushed (--dry-run).`)
		return
	}

	const cf = new CfAccessClient(required('CF_API_TOKEN'), required('CF_ACCOUNT_ID'))
	const accessApps: Record<string, string> = {}

	for (const decl of declarations) {
		const readback = await reconcileAccess(cf, decl.app, decl.access)
		const policies = readback.policies.map((p) => `${p.key}:${p.kind}`).join(', ')
		console.log(`✓ ${decl.app.padEnd(12)} ${readback.policies.length} reusable policy(ies): ${policies}`)

		// Collect aud → appId for the gated CF apps (those carrying a non-public rule) so the
		// PROPUSTKA_ACCESS_APPS Worker var can be pasted. Bypass-only apps need no aud entry.
		for (const cfApp of decl.access.apps) {
			if (cfApp.rules.every((r) => r.kind === 'public')) {
				continue
			}
			const app = await cf.findAppByName(cfApp.name)
			if (app) {
				accessApps[app.aud] = decl.app
			}
		}
	}

	console.log('\n— PROPUSTKA_ACCESS_APPS (paste into the propustka prod GitHub Environment variable) —')
	console.log(JSON.stringify(accessApps))
	console.log('\nDone. Access rules reconciled to reusable policies (legacy inline policies dropped off).')
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
