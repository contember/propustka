import type { AppGates } from '@propustka/client'
import { exampleAppId } from './propustka.schema'

/**
 * The example app's per-path gates, declared in code and enforced IN-PROCESS by `PropustkaAuth`
 * (the propustka-native successor to the deleted Cloudflare Access edge rules).
 *
 * Where `propustka.schema.ts` declares the app's authz vocabulary, this declares WHICH credential
 * KIND each path requires. There is no reconcile — these rules are pure SDK config. Array order is
 * the precedence (first matching+satisfiable rule wins); a path matching no rule is denied.
 */
export const exampleGates: AppGates = {
	rules: [
		// Public carve-out (was the `example-app-public` bypass CF app).
		{ path: '/public/*', kind: 'public' },
		// Gated host: a machine `px_` key (Authorization: Bearer) OR a logged-in human — the two-rule
		// CF app, now two precedence-ordered gate rules sharing the `/*` glob.
		{ path: '/*', kind: 'service' },
		{ path: '/*', kind: 'human' },
	],
}

// Re-exported so callers read one source for the app id.
export { exampleAppId }
