// Deploy-time schema reconcile — Access-as-code, authz edition.
//
// Each app OWNS its authz vocabulary (scope dimensions, action catalog, roles) and declares it
// in its own code as an `AppSchema`. At deploy time the app reconciles that declaration into
// Propustka by PUTting it to the idempotent admin endpoint `PUT /admin/apps/:app/schema`, so the
// IAM Worker's DB always mirrors what the app actually checks at runtime.
//
// This is a DEPLOY/OPERATOR helper, NOT a runtime one: it talks HTTP to the admin origin (not the
// `IAM` service binding), because reconcile is a privileged admin operation gated by Cloudflare
// Access — service bindings carry no caller identity and must never authorize it. Call it from a
// deploy step / provisioning script, never from request handling.
//
// Idempotent: the endpoint upserts scopes/actions/origin='app' roles and deletes app-origin rows
// absent from the body; origin='custom' policies are never touched. Re-running is safe.

import type { AppSchema } from '@propustka/core'

export interface ReconcileSchemaOptions {
	/** The IAM Worker's admin origin, e.g. `https://propustka.example.com` (trailing slash ok). */
	url: string
	/** The app id — must be a configured `ACCESS_APPS` value on the target Propustka. */
	app: string
	/** The app's declared vocabulary. */
	schema: AppSchema
	/**
	 * Access SERVICE TOKEN for a remote (operator) run: Access validates the pair at the edge and
	 * forwards the JWT the admin gate reads. Omit BOTH for a local run — the Worker's
	 * `ENVIRONMENT=local` + empty `ACCESS_APPS` resolves a fixed global-admin for token-less calls.
	 */
	accessClientId?: string
	accessClientSecret?: string
}

/** Thrown when the admin endpoint rejects the reconcile; `status` is the HTTP status. */
export class ReconcileSchemaError extends Error {
	constructor(message: string, readonly status: number) {
		super(message)
		this.name = 'ReconcileSchemaError'
	}
}

/** Pull a human-readable message out of the admin API's `{ error }` body, if present. */
function errorMessage(value: unknown): string | null {
	if (typeof value !== 'object' || value === null || !('error' in value)) {
		return null
	}
	const message = value.error
	return typeof message === 'string' ? message : null
}

/**
 * Reconcile one app's declared `AppSchema` into Propustka (idempotent). Resolves on success;
 * throws `ReconcileSchemaError` on a non-2xx response, or `Error` on a half-set service token.
 */
export async function reconcileSchema(options: ReconcileSchemaOptions): Promise<void> {
	const { url, app, schema, accessClientId, accessClientSecret } = options

	// Both-or-neither: a half-set service token would silently 401 at the Access edge.
	if ((accessClientId === undefined) !== (accessClientSecret === undefined)) {
		throw new Error('reconcileSchema: set BOTH accessClientId and accessClientSecret, or neither (local dev bypass)')
	}

	const headers: Record<string, string> = { 'content-type': 'application/json' }
	if (accessClientId !== undefined && accessClientSecret !== undefined) {
		headers['CF-Access-Client-Id'] = accessClientId
		headers['CF-Access-Client-Secret'] = accessClientSecret
	}

	// Trim a trailing slash so `${base}${path}` never doubles up.
	const base = url.replace(/\/+$/, '')
	const response = await fetch(`${base}/admin/apps/${encodeURIComponent(app)}/schema`, {
		method: 'PUT',
		headers,
		body: JSON.stringify(schema),
	})
	if (!response.ok) {
		const payload: unknown = await response.json().catch(() => null)
		const detail = errorMessage(payload) ?? response.statusText
		throw new ReconcileSchemaError(`PUT /admin/apps/${app}/schema failed (${response.status}): ${detail}`, response.status)
	}
}
