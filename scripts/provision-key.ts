#!/usr/bin/env bun
/**
 * Mint a per-app PROVISIONING KEY — a Cloudflare Access service token + a propustka service principal
 * carrying a grant — via the admin endpoint `POST /admin/api-keys`. The target app uses the returned
 * clientId/clientSecret as its CI `PROPUSTKA_ACCESS_CLIENT_ID/SECRET` to self-reconcile its schema +
 * Access rules at deploy time. This replaces hand-creating Zero Trust service tokens in the dashboard.
 *
 * For now the key is granted the built-in cross-app `admin` role — the SAME privilege contember prod
 * uses today. Least-privilege per-app reconcile authz (a key scoped to only its own app) is a tracked
 * follow-up that needs propustka to declare its own platform schema + relax the admin gate.
 *
 *   PROPUSTKA_URL=https://propustka.example.com         # the IAM Worker's admin origin
 *   # Auth — the admin API is gated by Cloudflare Access. Pick ONE:
 *   #  • an ADMIN Access service token (operator/CI):
 *   PROPUSTKA_ACCESS_CLIENT_ID=…
 *   PROPUSTKA_ACCESS_CLIENT_SECRET=…
 *   #  • first bootstrap (no admin key yet): provision the key in the admin UI instead (human login).
 *   bun run scripts/provision-key.ts --app <appId> [--label <label>] [--dry-run]
 */

interface ProvisionApiKeyResponse {
	principalId: string
	clientId: string
	clientSecret: string
	tokenId?: string
	policyInclusion?: string
}

function arg(name: string): string | undefined {
	const i = process.argv.indexOf(`--${name}`)
	return i !== -1 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined
}

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

async function main(): Promise<void> {
	const app = arg('app')
	if (app === undefined || app === '') {
		throw new Error('Usage: provision-key.ts --app <appId> [--label <label>] [--dry-run]')
	}
	const label = arg('label') ?? `${app}-provisioning`

	if (DRY_RUN) {
		console.log(`DRY RUN — would mint a 'service' provisioning key for app '${app}' (label '${label}', roleKey 'admin', cross-app).`)
		return
	}

	const url = required('PROPUSTKA_URL').replace(/\/+$/, '')
	const clientId = optional('PROPUSTKA_ACCESS_CLIENT_ID')
	const clientSecret = optional('PROPUSTKA_ACCESS_CLIENT_SECRET')
	// Both-or-neither: a half-set service token would silently 401 at the Access edge.
	if ((clientId === undefined) !== (clientSecret === undefined)) {
		throw new Error('Set BOTH PROPUSTKA_ACCESS_CLIENT_ID and PROPUSTKA_ACCESS_CLIENT_SECRET, or neither (UI bootstrap).')
	}

	const headers: Record<string, string> = { 'content-type': 'application/json' }
	if (clientId !== undefined && clientSecret !== undefined) {
		headers['CF-Access-Client-Id'] = clientId
		headers['CF-Access-Client-Secret'] = clientSecret
	}

	// app: null → a cross-app key; the built-in `admin` role resolves for every verified app.
	const response = await fetch(`${url}/admin/api-keys`, {
		method: 'POST',
		headers,
		body: JSON.stringify({ type: 'service', label, app: null, roleKey: 'admin' }),
	})
	const payload: unknown = await response.json().catch(() => null)
	if (!response.ok) {
		const detail = payload !== null && typeof payload === 'object' && 'error' in payload
			? String((payload as { error: unknown }).error)
			: response.statusText
		throw new Error(`POST /admin/api-keys failed (${response.status}): ${detail}`)
	}

	const result = payload as ProvisionApiKeyResponse
	console.log(`✓ Provisioning key minted for '${app}' (principal ${result.principalId}).\n`)
	console.log("Store these as the app's CI secrets — shown ONCE:")
	console.log(`  PROPUSTKA_ACCESS_CLIENT_ID=${result.clientId}`)
	console.log(`  PROPUSTKA_ACCESS_CLIENT_SECRET=${result.clientSecret}`)
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
