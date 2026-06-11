#!/usr/bin/env bun
/**
 * Provision Cloudflare Access applications + policies for the propustka / poplach / opice
 * stack — Access-as-code (IaC-lite). Idempotent: matches apps by name, creates the missing
 * ones, ensures each has its policy, and prints every AUD tag plus a ready-to-paste
 * `PROPUSTKA_ACCESS_APPS` value.
 *
 * Run it yourself (the operator holds the token; nothing here is committed or logged):
 *
 *   CF_API_TOKEN=…                    # Zero Trust → Access: Apps and Policies — Edit
 *   CF_ACCOUNT_ID=…
 *   ACCESS_DOMAIN=example.com         # hostnames become iam. / poplach. / opice.<domain>
 *   ACCESS_OPERATOR_EMAILS=a@x.cz,b@x.cz
 *   ACCESS_ADMIN_EMAILS=a@x.cz        # optional; defaults to ACCESS_OPERATOR_EMAILS
 *   bun run scripts/provision-access.ts [--dry-run]
 *
 * This provisions ONLY Access (the edge authn). The Worker routes
 * (iam./poplach./opice.<domain> → the deployed Workers) are added separately at/after
 * deploy — Access only gates traffic that reaches the zone. The two bypass apps
 * (poplach-ingest, opice-public) carve the public data paths out of their host's
 * Allow app; Cloudflare matches the most specific path first, so order does not matter.
 */

const API_BASE = 'https://api.cloudflare.com/client/v4'

// ── env ──────────────────────────────────────────────────────────────────────

function required(name: string): string {
	const value = process.env[name]
	if (value === undefined || value === '') {
		throw new Error(`Missing required env var ${name}`)
	}
	return value
}

function emailList(name: string, fallback?: string[]): string[] {
	const raw = process.env[name]
	if (raw === undefined || raw.trim() === '') {
		if (fallback) return fallback
		throw new Error(`Missing required env var ${name} (comma-separated emails)`)
	}
	return raw.split(',').map((e) => e.trim()).filter((e) => e.length > 0)
}

const DRY_RUN = process.argv.includes('--dry-run')

// ── minimal CF Access API client (mirrors src/cfaccess.ts) ────────────────────

/** Read an own string-keyed property as `unknown` without an `as` cast. */
function prop(value: unknown, key: string): unknown {
	if (typeof value !== 'object' || value === null) return undefined
	if (!Object.prototype.hasOwnProperty.call(value, key)) return undefined
	return (value as Record<string, unknown>)[key]
}

interface CfEnvelope {
	success: boolean
	result: unknown
	errors: { message: string }[]
}

function isEnvelope(value: unknown): value is CfEnvelope {
	return typeof prop(value, 'success') === 'boolean'
}

function envelopeErrors(value: CfEnvelope): string {
	if (!Array.isArray(value.errors)) return ''
	return value.errors
		.map((e) => prop(e, 'message'))
		.filter((m): m is string => typeof m === 'string')
		.join('; ')
}

class CfError extends Error {
	constructor(message: string, readonly status: number) {
		super(message)
		this.name = 'CfError'
	}
}

class Cf {
	constructor(private readonly token: string, private readonly accountId: string) {}

	async request(method: string, path: string, body?: unknown): Promise<unknown> {
		const response = await fetch(`${API_BASE}/accounts/${this.accountId}${path}`, {
			method,
			headers: { authorization: `Bearer ${this.token}`, 'content-type': 'application/json' },
			...(body === undefined ? {} : { body: JSON.stringify(body) }),
		})
		const payload: unknown = await response.json()
		if (!isEnvelope(payload) || !response.ok || !payload.success) {
			const detail = isEnvelope(payload) ? envelopeErrors(payload) || response.statusText : response.statusText
			throw new CfError(`Cloudflare API ${method} ${path} failed: ${detail}`, response.status)
		}
		return payload.result
	}
}

// ── app model ─────────────────────────────────────────────────────────────────

type Decision = 'allow' | 'bypass'
type IncludeRule = { email: { email: string } } | { everyone: Record<string, never> }

interface AppSpec {
	/** identity in the PROPUSTKA_ACCESS_APPS map; null = a bypass app whose AUD we don't need. */
	appId: string | null
	name: string
	destinations: string[]
	decision: Decision
	include: IncludeRule[]
}

function buildSpecs(domain: string, operators: string[], admins: string[]): AppSpec[] {
	const allow = (emails: string[]): IncludeRule[] => emails.map((email) => ({ email: { email } }))
	const everyone: IncludeRule[] = [{ everyone: {} }]
	return [
		{ appId: 'propustka', name: 'propustka-admin', destinations: [`propustka.${domain}`], decision: 'allow', include: allow(admins) },
		{ appId: 'poplach', name: 'poplach', destinations: [`poplach.${domain}`], decision: 'allow', include: allow(operators) },
		{
			appId: null,
			name: 'poplach-ingest',
			destinations: [`poplach.${domain}/api/*/envelope`, `poplach.${domain}/api/sourcemaps`],
			decision: 'bypass',
			include: everyone,
		},
		{ appId: 'opice', name: 'opice-operator', destinations: [`opice.${domain}`], decision: 'allow', include: allow(operators) },
		{
			appId: null,
			name: 'opice-public',
			destinations: [`opice.${domain}/api/v1`, `opice.${domain}/s`, `opice.${domain}/install.md`],
			decision: 'bypass',
			include: everyone,
		},
	]
}

// ── reconcile ──────────────────────────────────────────────────────────────────

interface AppRecord {
	id: string
	aud: string
}

function asAppRecord(value: unknown): AppRecord | null {
	const id = prop(value, 'id')
	const aud = prop(value, 'aud')
	if (typeof id !== 'string' || typeof aud !== 'string') return null
	return { id, aud }
}

async function findAppByName(cf: Cf, name: string): Promise<AppRecord | null> {
	for (let page = 1; page <= 100; page++) {
		const result = await cf.request('GET', `/access/apps?per_page=50&page=${page}`)
		if (!Array.isArray(result) || result.length === 0) return null
		for (const item of result) {
			if (prop(item, 'name') === name) {
				const record = asAppRecord(item)
				if (!record) throw new CfError(`Access app "${name}" has an unexpected shape (no id/aud)`, 502)
				return record
			}
		}
		if (result.length < 50) return null
	}
	return null
}

async function createApp(cf: Cf, spec: AppSpec): Promise<AppRecord> {
	const result = await cf.request('POST', '/access/apps', {
		name: spec.name,
		domain: spec.destinations[0],
		type: 'self_hosted',
		session_duration: '24h',
		destinations: spec.destinations.map((uri) => ({ type: 'public', uri })),
	})
	const record = asAppRecord(result)
	if (!record) throw new CfError(`Created Access app "${spec.name}" returned no id/aud`, 502)
	return record
}

async function ensurePolicy(cf: Cf, appId: string, spec: AppSpec): Promise<boolean> {
	const existing = await cf.request('GET', `/access/apps/${appId}/policies`)
	if (Array.isArray(existing) && existing.length > 0) return false
	await cf.request('POST', `/access/apps/${appId}/policies`, {
		name: `${spec.name}-policy`,
		decision: spec.decision,
		include: spec.include,
	})
	return true
}

// ── main ────────────────────────────────────────────────────────────────────

async function main(): Promise<void> {
	const cf = new Cf(required('CF_API_TOKEN'), required('CF_ACCOUNT_ID'))
	const domain = required('ACCESS_DOMAIN')
	const operators = emailList('ACCESS_OPERATOR_EMAILS')
	const admins = emailList('ACCESS_ADMIN_EMAILS', operators)
	const specs = buildSpecs(domain, operators, admins)

	if (DRY_RUN) {
		console.log('DRY RUN — no changes. Would reconcile these Access apps:\n')
		for (const spec of specs) {
			console.log(`  • ${spec.name}  [${spec.decision}]`)
			for (const uri of spec.destinations) console.log(`      ${uri}`)
		}
		return
	}

	const accessApps: Record<string, string> = {}
	for (const spec of specs) {
		const existing = await findAppByName(cf, spec.name)
		const app = existing ?? (await createApp(cf, spec))
		const policyCreated = await ensurePolicy(cf, app.id, spec)
		const appState = existing ? 'exists' : 'created'
		const policyState = policyCreated ? 'policy created' : 'policy kept'
		console.log(`✓ ${spec.name.padEnd(16)} ${appState.padEnd(8)} ${policyState.padEnd(15)} aud=${app.aud}`)
		if (spec.appId) accessApps[app.aud] = spec.appId
	}

	console.log('\n— PROPUSTKA_ACCESS_APPS (paste into the propustka prod GitHub Environment variable) —')
	console.log(JSON.stringify(accessApps))
	console.log('\nNext: add the Worker routes (propustka./poplach./opice.' + domain + ' → the deployed Workers)')
	console.log('so Access actually fronts them, then deploy propustka.')
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
