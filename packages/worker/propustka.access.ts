import type { AppAccess } from '@propustka/core'

/**
 * propustka-admin's OWN Cloudflare Access front door, declared in code (Access-as-code, EDGE edition).
 *
 * propustka is just another app behind Access: this declares WHO reaches the admin SPA + the HTTP
 * admin API (`/admin/*`) on the IAM Worker's own hostname. `scripts/provision-access.ts` reconciles
 * it DIRECTLY into Cloudflare with the operator token — the one irreducible BOOTSTRAP that breaks the
 * chicken-and-egg: the admin endpoint every other app's reconcile goes through can't gate itself
 * until THIS front door exists. Every downstream app declares its own `propustka.access.ts` (e.g.
 * poplach's) and self-reconciles via that admin endpoint once propustka-admin is up.
 *
 * Per-target, like poplach's: the hostname comes from `PROPUSTKA_HOSTNAME` (the same deploy var
 * `oblaka.ts` binds as the Custom Domain) and the human email domains from
 * `PROPUSTKA_ADMIN_EMAIL_DOMAINS` — so contember prod and manGoweb each front their own domain +
 * operators without the values being hardcoded to one account. Falls back to the contember values
 * for a local `--dry-run`.
 */

/**
 * The app id propustka-admin reconciles under — the value the propustka-admin Access app's `aud`
 * maps to in `PROPUSTKA_ACCESS_APPS`.
 */
export const propustkaAppId = 'propustka'

const host = process.env['PROPUSTKA_HOSTNAME'] ?? 'propustka.contember.com'

const adminEmailDomains = (process.env['PROPUSTKA_ADMIN_EMAIL_DOMAINS'] ?? 'contember.com')
	.split(',')
	.map((d) => d.trim())
	.filter(Boolean)

export const propustkaAccess: AppAccess = {
	apps: [
		{
			// The gated admin host: machines (service tokens — app provisioning keys) AND humans.
			key: 'admin',
			name: 'propustka-admin',
			destinations: [host],
			sessionDuration: '24h',
			rules: [
				{ kind: 'service-auth' },
				{ kind: 'human', emailDomains: adminEmailDomains },
			],
		},
	],
}
