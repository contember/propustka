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
 *   # Auth — the admin API is gated by propustka itself. Pick ONE:
 *   #  • local dev: no auth. The Worker's ENVIRONMENT=local + empty PROPUSTKA_SIGNING_KEYS resolves
 *   #    a fixed global-admin identity for credential-less requests, so a local run needs nothing.
 *   #  • remote: a propustka-issued `px_` ADMIN key, sent as `Authorization: Bearer`.
 *   PROPUSTKA_ADMIN_KEY=px_…           # optional; the admin/provisioning key for a remote run
 *   bun run scripts/provision-schemas.ts [--dry-run]
 *
 * --dry-run parses every declaration and prints the intended reconcile (scopes / actions /
 * roles per app) without touching the Worker.
 *
 * To declare + push a NEW app: add a `propustka.schema.ts` exporting a typed `AppSchema` and
 * its app id, register it in `DECLARATIONS` below, then run this script (its first reconcile
 * registers the app).
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

// The actual PUT + bearer auth + error shaping live in `reconcileSchema` (@propustka/client),
// so any app's own deploy step reconciles exactly the way this does.

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
	const adminKey = optional('PROPUSTKA_ADMIN_KEY')
	const authMode = adminKey !== undefined ? 'px_ admin key (bearer)' : 'no auth (local dev bypass)'
	console.log(`Reconciling ${DECLARATIONS.length} app schema(s) against ${url} (${authMode})\n`)

	for (const decl of DECLARATIONS) {
		// reconcileSchema (@propustka/client) does the idempotent PUT with bearer auth.
		await reconcileSchema({ url, app: decl.app, schema: decl.schema, ...(adminKey === undefined ? {} : { adminKey }) })
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
