#!/usr/bin/env bun
/**
 * Reconcile each app's DECLARED authz vocabulary into Propustka — Access-as-code, authz
 * edition. Every app owns its scope dimensions, action catalog, and roles and declares them
 * in its own code (e.g. `examples/app/propustka.schema.ts`); this script PUTs each declared
 * `AppSchema` to the idempotent admin endpoint `PUT /admin/apps/:app/schema`, so the IAM
 * Worker's DB always mirrors what the app actually checks at runtime.
 *
 * Idempotent: the endpoint upserts scopes/actions/origin='app' roles and deletes app-origin
 * rows absent from the body; origin='custom' policies are never touched. Re-running is safe.
 *
 * Run it yourself (the operator targets a deployed/local Worker; nothing here is committed):
 *
 *   PROPUSTKA_URL=https://propustka.example.com    # the IAM Worker's admin origin
 *   # Auth — the admin API is gated by Cloudflare Access. Pick ONE:
 *   #  • local dev: no auth. The Worker's ENVIRONMENT=local + empty ACCESS_APPS resolves a
 *   #    fixed global-admin identity for token-less requests, so a local run needs nothing.
 *   #  • remote: an Access SERVICE TOKEN with admin permission. Access validates the pair at
 *   #    the edge and forwards the JWT the admin gate reads.
 *   PROPUSTKA_ACCESS_CLIENT_ID=…       # optional; the service token's Client ID
 *   PROPUSTKA_ACCESS_CLIENT_SECRET=…   # optional; the service token's Client Secret
 *   bun run scripts/provision-schemas.ts [--dry-run]
 *
 * --dry-run parses every declaration and prints the intended reconcile (scopes / actions /
 * roles per app) without touching the Worker.
 *
 * To declare + push a NEW app: add a `propustka.schema.ts` exporting a typed `AppSchema` and
 * its app id, register it in `DECLARATIONS` below, ensure the target Propustka knows the app
 * id (an `ACCESS_APPS` value), then run this script.
 */

import { reconcileSchema } from '@propustka/client'
import type { AppSchema } from '@propustka/core'
import { exampleAppId, exampleAppSchema } from '../examples/app/propustka.schema'

// ── declarations ──────────────────────────────────────────────────────────────
//
// One entry per app whose vocabulary this operator reconciles. Each is the app's OWN
// typed declaration imported from its code — the schema lives with the app, not here.

interface SchemaDeclaration {
	app: string
	schema: AppSchema
}

const DECLARATIONS: SchemaDeclaration[] = [
	{ app: exampleAppId, schema: exampleAppSchema },
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

// The actual PUT + both-or-neither token guard + error shaping live in `reconcileSchema`
// (@propustka/client), so any app's own deploy step reconciles exactly the way this does.

// ── reporting ─────────────────────────────────────────────────────────────────

function describe(decl: SchemaDeclaration): string[] {
	const { app, schema } = decl
	const lines = [`  • ${app}`]
	lines.push(`      scopes:  ${schema.scopes.map((s) => s.type).join(', ') || '(none)'}`)
	lines.push(`      actions: ${schema.actions.map((a) => a.action).join(', ') || '(none)'}`)
	const roles = Object.entries(schema.roles).map(([key, def]) => `${key} [${def.permissions.join(' ')}]`)
	lines.push(`      roles:   ${roles.join('; ') || '(none)'}`)
	return lines
}

// ── main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
	if (DRY_RUN) {
		console.log('DRY RUN — no changes. Would reconcile these app schemas:\n')
		for (const decl of DECLARATIONS) {
			for (const line of describe(decl)) console.log(line)
		}
		console.log(`\n${DECLARATIONS.length} app schema(s) — none pushed (--dry-run).`)
		return
	}

	const url = required('PROPUSTKA_URL')
	const accessClientId = optional('PROPUSTKA_ACCESS_CLIENT_ID')
	const accessClientSecret = optional('PROPUSTKA_ACCESS_CLIENT_SECRET')
	const authMode = accessClientId !== undefined ? 'Access service token' : 'no auth (local dev bypass)'
	console.log(`Reconciling ${DECLARATIONS.length} app schema(s) against ${url} (${authMode})\n`)

	for (const decl of DECLARATIONS) {
		// reconcileSchema (@propustka/client) does the idempotent PUT + both-or-neither guard.
		await reconcileSchema({ url, app: decl.app, schema: decl.schema, accessClientId, accessClientSecret })
		const scopes = decl.schema.scopes.length
		const actions = decl.schema.actions.length
		const roles = Object.keys(decl.schema.roles).length
		console.log(`✓ ${decl.app.padEnd(16)} ${scopes} scope(s), ${actions} action(s), ${roles} role(s)`)
	}

	console.log('\nDone. Schemas are reconciled (idempotent — origin=custom policies untouched).')
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
