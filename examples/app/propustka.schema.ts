import type { AppSchema } from '@propustka/core'

/**
 * The example app's authz vocabulary, declared in code (Access-as-code, authz edition).
 *
 * Each app OWNS its scope dimensions, action catalog, and roles and DECLARES them here.
 * `scripts/provision-schemas.ts` reconciles this into Propustka via the idempotent
 * `PUT /admin/apps/:app/schema` endpoint, so the IAM Worker's DB always mirrors what the
 * app actually checks at runtime (the `can()` / `scopedTo()` calls in `src/index.ts`).
 *
 * Invariants (validated by the admin endpoint via core `isActionAllowed` — keep them true
 * so a push never 400s):
 *   - every role permission is `*`, an exact catalog action, or a `prefix.*` whose prefix
 *     covers at least one catalog action;
 *   - scope `type`s are the dimensions app code passes to `can(action, { type, value })`
 *     and `scopedTo(action, dimension)`.
 */
export const exampleAppSchema: AppSchema = {
	// Two independent scope dimensions (NO hierarchy between them — core treats them flatly).
	// `value`s are opaque app-owned ids; Propustka never interprets them.
	scopes: [
		{ type: 'organization', label: 'Organization' },
		{ type: 'project', label: 'Project' },
	],

	// The concrete actions this app exposes. Inline grants and role patterns reference
	// these strings; a `prefix.*` role pattern only validates because actions live under it.
	actions: [
		{ action: 'example.read', description: 'Read example data' },
		{ action: 'example.view', description: 'View the example surface' },
		{ action: 'example.settings.update', description: 'Update example settings' },
	],

	// origin='app' roles — the canonical bundles the app ships. An admin may layer
	// origin='custom' policies on top via the admin UI; reconcile never touches those.
	roles: {
		editor: {
			name: 'Editor',
			description: 'Read, view, and manage settings',
			permissions: ['example.read', 'example.view', 'example.settings.update'],
		},
		viewer: {
			name: 'Viewer',
			description: 'Read-only access',
			permissions: ['example.read', 'example.view'],
		},
		manager: {
			// `example.*` covers every action under the `example.` namespace (prefix wildcard).
			name: 'Manager',
			description: 'Full access to every example action',
			permissions: ['example.*'],
		},
	},
}

/**
 * The app id this schema is reconciled under — the SAME id the app passes to
 * `new IamClient(env.IAM, 'example-app')` in `src/index.ts`, and a value the target
 * Propustka must know (an `ACCESS_APPS` value). The reconcile script reads this so the
 * declaration is the single source of truth for both the id and the vocabulary.
 */
export const exampleAppId = 'example-app'
