#!/usr/bin/env bun
/**
 * Reconcile each app's DECLARED Cloudflare Access edge rules into Propustka — Access-as-code, EDGE
 * edition (the front-door counterpart of `provision-schemas.ts`). Every app owns its Access rules
 * (service-auth / human / public) and declares them in its own code (e.g.
 * `examples/app/propustka.access.ts`); this PUTs each declared `AppAccess` to the idempotent admin
 * endpoint `PUT /admin/apps/:app/access`, and the IAM Worker reconciles Cloudflare's account-level
 * REUSABLE policies to match.
 *
 * This is the SDK / admin-endpoint path — how an APP reconciles its own rules at deploy time. The
 * Worker performs the Cloudflare mutations with ITS api token (needs *Access: Apps and Policies —
 * Edit*). The whole-stack BOOTSTRAP/MIGRATION (and propustka-admin's own front door, which gates
 * this very endpoint) is the operator's direct-CF `scripts/provision-access.ts` instead.
 *
 * Idempotent: reconcile owns only `px:<app>:` policies, updates them in place, and never touches
 * admin-made ones. Re-running is safe.
 *
 *   PROPUSTKA_URL=https://propustka.example.com    # the IAM Worker's admin origin
 *   # Auth — the admin API is gated by Cloudflare Access. Pick ONE:
 *   #  • local dev: no auth (ENVIRONMENT=local + empty ACCESS_APPS resolves a fixed global-admin).
 *   #  • remote: an Access SERVICE TOKEN with admin permission.
 *   PROPUSTKA_ACCESS_CLIENT_ID=…       # optional; the service token's Client ID
 *   PROPUSTKA_ACCESS_CLIENT_SECRET=…   # optional; the service token's Client Secret
 *   bun run scripts/provision-access-rules.ts [--dry-run]
 *
 * --dry-run parses every declaration and prints the intended reconcile (per CF app + rules) without
 * touching the Worker.
 *
 * To declare + push a NEW app: add a `propustka.access.ts` exporting a typed `AppAccess` and its app
 * id, register it in `DECLARATIONS` below, ensure the target Propustka knows the app id (an
 * `ACCESS_APPS` value), then run this script.
 */

import { reconcileAccess } from '@propustka/client'
import type { AppAccess } from '@propustka/core'
import { exampleAppAccess, exampleAppId } from '../examples/app/propustka.access'

// ── declarations ──────────────────────────────────────────────────────────────
//
// One entry per app whose Access edge rules this operator reconciles. Each is the app's OWN typed
// declaration imported from its code — the rules live with the app, not here.

interface AccessDeclaration {
	app: string
	access: AppAccess
}

const DECLARATIONS: AccessDeclaration[] = [
	{ app: exampleAppId, access: exampleAppAccess },
]

// ── env ─────────────────────────────────────────────────────────────────────────

function required(name: string): string {
	const value = process.env[name]
	if (value === undefined || value === '') {
		throw new Error(`Missing required env var ${name}`)
	}
	return value
}

function optional(name: string): string | undefined {
	const value = process.env[name]
	return value === undefined || value === '' ? undefined : value
}

const DRY_RUN = process.argv.includes('--dry-run')

// ── reporting ─────────────────────────────────────────────────────────────────

function describe(decl: AccessDeclaration): string[] {
	const lines = [`  • ${decl.app}`]
	for (const cfApp of decl.access.apps) {
		const rules = cfApp.rules.map((r) => r.kind).join(', ')
		lines.push(`      ${cfApp.name}  [${cfApp.destinations.join(', ')}]`)
		lines.push(`          rules: ${rules || '(none)'}`)
	}
	return lines
}

// ── main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
	if (DRY_RUN) {
		console.log('DRY RUN — no changes. Would reconcile these app Access rules:\n')
		for (const decl of DECLARATIONS) {
			for (const line of describe(decl)) console.log(line)
		}
		console.log(`\n${DECLARATIONS.length} app(s) — none pushed (--dry-run).`)
		return
	}

	const url = required('PROPUSTKA_URL')
	const accessClientId = optional('PROPUSTKA_ACCESS_CLIENT_ID')
	const accessClientSecret = optional('PROPUSTKA_ACCESS_CLIENT_SECRET')
	const authMode = accessClientId !== undefined ? 'Access service token' : 'no auth (local dev bypass)'
	console.log(`Reconciling ${DECLARATIONS.length} app Access rule(s) against ${url} (${authMode})\n`)

	for (const decl of DECLARATIONS) {
		await reconcileAccess({ url, app: decl.app, access: decl.access, accessClientId, accessClientSecret })
		const cfApps = decl.access.apps.length
		const rules = decl.access.apps.reduce((n, a) => n + a.rules.length, 0)
		console.log(`✓ ${decl.app.padEnd(16)} ${cfApps} CF app(s), ${rules} rule(s)`)
	}

	console.log('\nDone. Access rules are reconciled (idempotent — non-managed policies untouched).')
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
