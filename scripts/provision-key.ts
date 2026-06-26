#!/usr/bin/env bun
/**
 * Mint a per-app PROVISIONING KEY — a propustka-NATIVE service principal (carrying a grant) plus an
 * opaque `px_` key — via the admin endpoint `POST /admin/api-keys`. The target app stores the returned
 * `apiKey` as its CI `PROPUSTKA_ADMIN_KEY` and uses it (as `Authorization: Bearer`) to self-reconcile
 * its schema at deploy time. No Cloudflare Access, no Zero Trust service token.
 *
 * For now the key is granted the built-in cross-app `admin` role — the SAME privilege contember prod
 * uses today. Least-privilege per-app reconcile authz (a key scoped to only its own app) is a tracked
 * follow-up that needs propustka to declare its own platform schema + relax the admin gate.
 *
 *   PROPUSTKA_URL=https://propustka.example.com         # the IAM Worker's admin origin
 *   # Auth — the admin API is gated by propustka itself. Pick ONE:
 *   #  • an existing ADMIN `px_` key (operator/CI):
 *   PROPUSTKA_ADMIN_KEY=px_…
 *   #  • first bootstrap (no admin key yet): provision the key in the admin UI instead (human login).
 *   bun run scripts/provision-key.ts --app <appId> [--label <label>] [--dry-run]
 */

interface ProvisionApiKeyResponse {
	principalId: string
	apiKey: string
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
	const adminKey = optional('PROPUSTKA_ADMIN_KEY')

	const headers: Record<string, string> = { 'content-type': 'application/json' }
	if (adminKey !== undefined) {
		headers.authorization = `Bearer ${adminKey}`
	}
	// propustka's admin CSRF guard rejects state-changing requests whose Origin/Referer doesn't match
	// its own origin (a browser sends Origin for free; an operator script must set it explicitly).
	headers.Origin = new URL(url).origin

	// app: null → a cross-app key; the built-in `admin` role resolves for every app.
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
	console.log("Store this as the app's CI secret — shown ONCE:")
	console.log(`  PROPUSTKA_ADMIN_KEY=${result.apiKey}`)
}

main().catch((error: unknown) => {
	const message = error instanceof Error ? error.message : String(error)
	console.error(`\n✗ ${message}`)
	process.exit(1)
})
