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
 * Per-target hostname is REQUIRED, from `PROPUSTKA_HOSTNAME` (the same deploy var `oblaka.ts` binds
 * as the Custom Domain) — no hardcoded default. WHO the humans are is NOT declared here — propustka
 * owns that centrally (`HUMAN_EMAIL_DOMAINS` / `HUMAN_EMAILS`), applied to every app's human-gated
 * paths including this one. This app only declares that the admin host is service-auth + human-gated.
 */

/**
 * The app id propustka-admin reconciles under — the value the propustka-admin Access app's `aud`
 * maps to in `PROPUSTKA_ACCESS_APPS`.
 */
export const propustkaAppId = 'propustka'

const host = process.env['PROPUSTKA_HOSTNAME']
if (!host) {
	throw new Error('PROPUSTKA_HOSTNAME is not set — provide it for the deploy/reconcile (no hardcoded default).')
}

export const propustkaAccess: AppAccess = {
	apps: [
		{
			// The gated admin host: machines (service tokens — app provisioning keys) AND humans.
			// The human audience is propustka's central HUMAN_EMAIL_DOMAINS/HUMAN_EMAILS, not here.
			key: 'admin',
			name: 'propustka-admin',
			destinations: [host],
			sessionDuration: '24h',
			rules: [
				{ kind: 'service-auth' },
				{ kind: 'human' },
			],
		},
	],
}
