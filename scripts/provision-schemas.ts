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

// ── minimal admin API client ──────────────────────────────────────────────────

/**
 * Pull a human-readable message out of the admin API's `{ error }` body, if present.
 * The admin API's `error()` helper shapes every failure as `{ error: string }`.
 */
function errorMessage(value: unknown): string | null {
	if (typeof value !== 'object' || value === null || !('error' in value)) {
		return null
	}
	const message = value.error
	return typeof message === 'string' ? message : null
}

class PropustkaError extends Error {
	constructor(message: string, readonly status: number) {
		super(message)
		this.name = 'PropustkaError'
	}
}

interface ServiceToken {
	clientId: string
	clientSecret: string
}

class Propustka {
	private readonly base: string

	constructor(url: string, private readonly serviceToken: ServiceToken | null) {
		// Trim a trailing slash so `${base}${path}` never doubles up.
		this.base = url.replace(/\/+$/, '')
	}

	/** PUT an app's schema; returns the reconciled vocabulary the endpoint echoes back. */
	async putSchema(app: string, schema: AppSchema): Promise<unknown> {
		const headers: Record<string, string> = { 'content-type': 'application/json' }
		// A remote run carries an Access service token; Access validates the pair at the edge
		// and forwards the JWT the admin gate reads. A local run sends neither (dev bypass).
		if (this.serviceToken) {
			headers['CF-Access-Client-Id'] = this.serviceToken.clientId
			headers['CF-Access-Client-Secret'] = this.serviceToken.clientSecret
		}
		const response = await fetch(`${this.base}/admin/apps/${encodeURIComponent(app)}/schema`, {
			method: 'PUT',
			headers,
			body: JSON.stringify(schema),
		})
		const payload: unknown = await response.json().catch(() => null)
		if (!response.ok) {
			const detail = errorMessage(payload) ?? response.statusText
			throw new PropustkaError(`PUT /admin/apps/${app}/schema failed (${response.status}): ${detail}`, response.status)
		}
		return payload
	}
}

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
	const clientId = optional('PROPUSTKA_ACCESS_CLIENT_ID')
	const clientSecret = optional('PROPUSTKA_ACCESS_CLIENT_SECRET')
	// Both-or-neither: a half-set service token would silently 401 at the edge.
	if ((clientId === undefined) !== (clientSecret === undefined)) {
		throw new Error('Set BOTH PROPUSTKA_ACCESS_CLIENT_ID and PROPUSTKA_ACCESS_CLIENT_SECRET, or neither (local dev bypass)')
	}
	const serviceToken: ServiceToken | null = clientId !== undefined && clientSecret !== undefined
		? { clientId, clientSecret }
		: null

	const propustka = new Propustka(url, serviceToken)
	const authMode = serviceToken ? 'Access service token' : 'no auth (local dev bypass)'
	console.log(`Reconciling ${DECLARATIONS.length} app schema(s) against ${url} (${authMode})\n`)

	for (const decl of DECLARATIONS) {
		await propustka.putSchema(decl.app, decl.schema)
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
