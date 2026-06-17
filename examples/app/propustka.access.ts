import type { AppAccess } from '@propustka/core'
import { exampleAppId } from './propustka.schema'

/**
 * The example app's Cloudflare Access edge rules, declared in code (Access-as-code, EDGE edition).
 *
 * The front-door counterpart of `propustka.schema.ts`: where the schema declares the app's authz
 * vocabulary, this declares WHO reaches the app at the Cloudflare Access edge. `reconcileAccess`
 * (@propustka/client, see `scripts/provision-access-rules.ts`) PUTs it to the idempotent
 * `PUT /admin/apps/:app/access` endpoint, and Propustka reconciles it into Cloudflare as
 * account-level REUSABLE policies attached to these apps.
 *
 * One propustka app id may front MORE THAN ONE Cloudflare Access application — here the gated host
 * plus a separate bypass carve-out for its public path. Each entry's `rules` array order is the
 * Cloudflare precedence order (service-auth before human is the convention).
 */
export const exampleAppAccess: AppAccess = {
	apps: [
		{
			// The gated host: machines (service tokens) AND humans on the example.com domain.
			key: 'app',
			name: 'example-app',
			destinations: ['example-app.example.com'],
			sessionDuration: '24h',
			rules: [
				{ kind: 'service-auth' },
				{ kind: 'human', emailDomains: ['example.com'] },
			],
		},
		{
			// A public carve-out: a bypass app on a sub-path that anyone may reach (no Access).
			key: 'public',
			name: 'example-app-public',
			destinations: ['example-app.example.com/public'],
			rules: [{ kind: 'public' }],
		},
	],
}

// The id this declaration reconciles under — the same id the schema reconciles under, and an
// `ACCESS_APPS` value the target Propustka must know. Re-exported so the script reads one source.
export { exampleAppId }
